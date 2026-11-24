"""Measure grounding of actual local investigation output against independent archive records."""

import asyncio
import json
import logging
import secrets
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from uuid import UUID, uuid4

import httpx

from backend.api import create_app
from backend.auth import LOCAL_AUDIENCE, LOCAL_ISSUER, Auth, mint
from backend.investigations.contracts import (
    AnalyticsEvent,
    DoneEvent,
    Event,
    EvidenceEvent,
    NodeEvent,
    ReportEvent,
)
from backend.investigations.routes import ADAPTER
from backend.investigations.service import InvestigationService
from backend.investigations.store import SQLiteStore
from backend.models import CveDetail, Filters
from backend.reader import SnapshotReader
from backend.smoke import live_server
from pipelines.config import configured_snapshot, project_environment
from pipelines.io import read_raw, selected_snapshot
from pipelines.normalize import nvd_history, required_capture
from pipelines.parse import parse_epss, parse_kev
from pipelines.publish import load_run


async def observe(
    client: httpx.AsyncClient,
    snapshot: UUID,
    request: dict,
) -> tuple[list[Event], dict]:
    start = monotonic()
    first = None
    frames = []
    async with client.stream(
        "POST",
        "/v1/investigations",
        headers={"Idempotency-Key": uuid4().hex},
        json={"snapshot_id": str(snapshot), **request},
    ) as response:
        response.raise_for_status()
        async for line in response.aiter_lines():
            if line.startswith("data: "):
                first = first or monotonic()
                frames.append(ADAPTER.validate_json(line[6:]))
    assert first is not None and isinstance(frames[-1], DoneEvent)
    assert frames[-1].payload.status == "completed"
    assert [frame.seq for frame in frames] == list(range(1, len(frames) + 1))
    assert sum(isinstance(frame, DoneEvent) for frame in frames) == 1
    assert [frame.payload.node for frame in frames if isinstance(frame, NodeEvent)] == [
        "plan",
        "research",
        "analyze",
        "validate",
    ]
    return frames, {
        "first_ms": round((first - start) * 1000, 2),
        "total_ms": round((monotonic() - start) * 1000, 2),
        "events": len(frames),
    }


async def streams(
    base: str,
    key: str,
    reader: SnapshotReader,
    cves: Sequence[str],
) -> list[tuple[str, list[Event], dict]]:
    observations = []
    async with httpx.AsyncClient(
        base_url=base,
        headers={"Authorization": f"Bearer {mint(key)}"},
        trust_env=False,
    ) as client:
        cases = [
            ("global-ranking", {"question": "Prioritize known exploited vulnerabilities"}),
            ("regional-unsupported", {"question": "What evidence is available for South America?"}),
            (
                "country-unavailable",
                {"question": "Evidence of exposure?", "filters": {"country_iso2": "PE"}},
            ),
        ]
        for cve, country in zip(cves, [None, "PE", "CA", None], strict=True):
            selected = await client.get(
                f"/v1/cves/{cve}",
                params={
                    "snapshot_id": str(reader.snapshot),
                    **({"country_iso2": country} if country else {}),
                },
            )
            selected.raise_for_status()
            detail = CveDetail.model_validate(selected.json())
            assert detail.geography.country_iso2 == country and detail.geography.count is None
            cases.append(
                (
                    f"mitigation/{cve}/{country or 'world'}",
                    {
                        "question": f"How to mitigate {cve}?",
                        "filters": {"country_iso2": country, "cve_ids": [cve]},
                        "mitigation": {
                            "cve_id": cve,
                            "evidence_ids": [row.evidence_id for row in detail.evidence],
                        },
                    },
                )
            )
        for name, request in cases:
            frames, spans = await observe(client, reader.snapshot, request)
            observations.append((name, frames, spans))
    return observations


def evaluate(
    root: Path, reader: SnapshotReader, observations: list[tuple[str, list[Event], dict]]
) -> dict:
    capture = selected_snapshot(root, reader.snapshot)
    run = load_run(capture)
    kev_reference = required_capture(run, "cisa")
    kev = {row.cveID: row for row in parse_kev(read_raw(capture, kev_reference)).vulnerabilities}
    epss_reference = required_capture(run, "epss")
    score_date, model_version, values = parse_epss(read_raw(capture, epss_reference))
    epss = dict(values.select("cve", "epss").iter_rows())
    nvd = nvd_history(root, run)
    cases = []
    for name, frames, spans in observations:
        report = next(frame.payload for frame in frames if isinstance(frame, ReportEvent))
        analytics = next(frame.payload for frame in frames if isinstance(frame, AnalyticsEvent))
        assert report.analysis_mode == "deterministic" and not report.usage
        assert report.snapshot_id == reader.snapshot and report.score_date == score_date.date()
        assert analytics.geography == "unavailable" and not analytics.observations
        evidence = {
            item.evidence_id: item
            for frame in frames
            if isinstance(frame, EvidenceEvent)
            for item in frame.payload.items
        }
        assert "unavailable" in report.geographic_note or "explicitly" in report.geographic_note
        if name.startswith("mitigation/"):
            assert not analytics.ranked_cve_ids and analytics.risk is None
            assert any(item.key.endswith("/mitigation") for item in report.claims)
        if name in {"regional-unsupported", "country-unavailable"}:
            assert not report.claims and not analytics.ranked_cve_ids and analytics.risk is None
        grounded = 0
        failures = []
        for claim in report.claims:
            cve, _, category = claim.key.partition("/")
            refs = [evidence.get(identifier) for identifier in claim.evidence_ids]
            expected = None
            if category == "kev" and cve in kev:
                expected = (
                    f"CISA records known exploitation of {cve} in its KEV catalog.",
                    "cisa",
                    cve,
                    kev_reference.checksum,
                )
            if category == "mitigation" and cve in kev and kev[cve].requiredAction:
                action = " ".join(kev[cve].requiredAction.split())
                expected = (
                    "CISA KEV required action: " + action,
                    "cisa",
                    cve,
                    kev_reference.checksum,
                )
            if category == "epss" and cve in epss:
                expected = (
                    f"FIRST EPSS for {cve} on {score_date.date()} is {epss[cve]:.5f}.",
                    "epss",
                    f"{score_date.date()}/{model_version}",
                    epss_reference.checksum,
                )
            if category == "cvss" and cve in nvd:
                record, reference = nvd[cve]
                metric = record.metrics.preferred()
                if metric:
                    expected = (
                        f"NVD reports a CVSS {metric.cvssData.version} base score "
                        f"of {metric.cvssData.baseScore} for {cve}.",
                        "nvd",
                        cve,
                        reference["checksum"],
                    )
            if (
                expected
                and refs
                and claim.text == expected[0]
                and all(
                    ref and (ref.source, ref.source_record_id, ref.checksum) == expected[1:]
                    for ref in refs
                )
            ):
                grounded += 1
            else:
                failures.append(claim.key)
        cases.append(
            {
                "scenario": name,
                "claims": len(report.claims),
                "grounded": grounded,
                "unsupported": failures,
                "geographic_observations": len(analytics.observations),
                "analysis_mode": report.analysis_mode,
                "usage": [],
                **spans,
            }
        )
    total = sum(case["claims"] for case in cases)
    grounded = sum(case["grounded"] for case in cases)
    assert total > 0
    return {
        "observed_at": datetime.now(UTC).isoformat(),
        "environment": "local-loopback",
        "snapshot": str(reader.snapshot),
        "cases": cases,
        "grounded": grounded,
        "factual_claims": total,
        "fraction": grounded / total,
        "claim_free_responses": sum(case["claims"] == 0 for case in cases),
        "paid_calls": 0,
    }


def main() -> None:
    logging.getLogger("aegis.timing").setLevel(logging.INFO)
    env = project_environment()
    root = Path(env.get("AEGIS_DATA_DIR") or "data").resolve()
    reader = SnapshotReader.duckdb(root, configured_snapshot(env))
    cves = [row.cve_id for row in reader.vulnerabilities(Filters(limit=4)).data]
    key = secrets.token_urlsafe(48)
    auth = Auth(issuer=LOCAL_ISSUER, audience=LOCAL_AUDIENCE, workspace="local", local_key=key)
    with TemporaryDirectory(prefix="aegis-grounding-") as directory:
        service = InvestigationService(
            SQLiteStore(Path(directory) / "checkpoint.db"), reader.snapshot
        )
        with live_server(create_app(reader, auth, service)) as base:
            observed = asyncio.run(streams(base, key, reader, cves))
        result = evaluate(root, reader, observed)
    print(json.dumps(result))
    if result["fraction"] < 0.95:
        raise SystemExit("Grounding minimum not met")


if __name__ == "__main__":
    main()
