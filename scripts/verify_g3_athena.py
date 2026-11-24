"""Check G3's additional query shapes against the authorized G2 lake."""

import argparse
import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from backend.cve_detail import detail
from backend.models import Edge, Exposure, Filters, RiskSummary, Vulnerability
from backend.reader import SnapshotReader, View
from infra.operations import stack_outputs
from infra.settings import SCAN_CUTOFF, SDK_CONFIG, Settings
from pipelines.athena import AthenaReader
from pipelines.cloud import SnapshotStore
from pipelines.config import configured_snapshot, project_environment

MAX_QUERIES = 8
# The conservative timeout-based monthly scenario documented in the G2 runbook.
OPERATING_ESTIMATE = Decimal("5.45")


def comparable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(UTC).replace(microsecond=value.microsecond // 1000 * 1000)
    if isinstance(value, list):
        return [comparable(item) for item in value]
    if isinstance(value, dict):
        return {key: comparable(item) for key, item in value.items()}
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extension", action="store_true")
    parser.add_argument("--confirmed-remaining-usd", type=Decimal)
    args = parser.parse_args()
    cap = 12 if args.extension else MAX_QUERIES
    allowance = Decimal(cap * SCAN_CUTOFF) * Decimal(5) / Decimal(10**12)
    if args.extension and (
        args.confirmed_remaining_usd is None
        or not args.confirmed_remaining_usd.is_finite()
        or args.confirmed_remaining_usd < allowance
    ):
        raise SystemExit("Confirm remaining G2 budget covering the extension query allowance")
    environment = project_environment()
    settings = Settings.load(environment=environment)
    ceiling = settings.authorize()
    if OPERATING_ESTIMATE + allowance > ceiling:
        raise SystemExit("G2 estimate and bounded query allowance exceed the G2 ceiling")
    session, _ = settings.identity()
    outputs = stack_outputs(session, settings)
    client = session.client("athena", config=SDK_CONFIG)
    config = client.get_work_group(WorkGroup=outputs["Workgroup"])["WorkGroup"]["Configuration"]
    result = config["ResultConfiguration"]
    if (
        not config["EnforceWorkGroupConfiguration"]
        or config["BytesScannedCutoffPerQuery"] != SCAN_CUTOFF
        or result.get("OutputLocation") != f"s3://{outputs['ResultsBucket']}/queries/"
        or result.get("EncryptionConfiguration", {}).get("EncryptionOption") != "SSE_KMS"
    ):
        raise SystemExit("G2 Athena workgroup cost controls differ")

    store = SnapshotStore(session.client("s3", config=SDK_CONFIG), outputs["LakeBucket"])
    snapshot = configured_snapshot(environment)
    release = store.release(snapshot)
    if snapshot is None or release is None:
        raise SystemExit("Both local and cloud pinned snapshots are required")
    local = SnapshotReader.duckdb(Path(environment.get("AEGIS_DATA_DIR") or "data"), snapshot)
    stats: list[dict[str, Any]] = []
    attempts = 0

    class BoundedReader(AthenaReader):
        def _select(
            self, sql: str, *, max_rows: int
        ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
            nonlocal attempts
            if attempts >= cap:
                raise RuntimeError("G3 parity query cap reached")
            attempts += 1
            records, metric = super()._select(sql, max_rows=max_rows)
            stats.append(metric)
            print(json.dumps(metric), flush=True)
            return records, metric

    def read_cisa() -> bytes:
        raw = store.read(f"snapshots/{snapshot}/raw/00-cisa.json")
        if raw is None or len(raw) > 4 * 1024 * 1024:
            raise RuntimeError("CISA archive is missing or exceeds its read cap")
        return raw

    remote = SnapshotReader.cloud(
        BoundedReader(client, settings.database, outputs["Workgroup"]),
        release,
        geo_available=local.geo_available,
        cisa_archive=read_cisa if args.extension else None,
    )
    first = local.vulnerabilities(Filters(limit=1)).data[0]
    if args.extension:
        left = detail(local, first.cve_id, snapshot, "PE")
        right = detail(remote, first.cve_id, snapshot, "PE")
        assert comparable(left.model_dump()) == comparable(right.model_dump())
        print(
            json.dumps(
                {
                    "snapshot": str(snapshot),
                    "cases_passed": 1,
                    "shape": "cve-detail",
                    "queries": attempts,
                    "bytes_scanned": sum(m["scanned_bytes"] for m in stats),
                    "worst_case_query_usd": str(allowance),
                }
            )
        )
        return
    exact = Filters(cve_ids=(first.cve_id,), date_from=first.kev_added_at, limit=12)
    for view, filters, model in (
        (View.KPIS, Filters(min_epss=0.5), RiskSummary),
        (View.CVES, Filters(min_epss=0.5, limit=20), Vulnerability),
        (View.CVES, exact, Vulnerability),
        (View.MAP, Filters(country_iso2="PE"), Exposure),
        (View.GRAPH, exact, Edge),
    ):
        left = local.view_rows(view, filters, model)
        right = remote.view_rows(view, filters, model)
        assert comparable([x.model_dump() for x in left]) == comparable(
            [x.model_dump() for x in right]
        ), view
        print(json.dumps({"view": view, "rows": len(left), "parity": True}), flush=True)
    left_evidence = local.evidence(first.source_refs[0]).model_dump()
    right_evidence = remote.evidence(first.source_refs[0]).model_dump()
    assert comparable(left_evidence) == comparable(right_evidence)
    print(
        json.dumps(
            {
                "snapshot": str(snapshot),
                "cases_passed": 6,
                "queries": len(stats),
                "bytes_scanned": sum(m["scanned_bytes"] for m in stats),
                "worst_case_query_usd": str(allowance),
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
