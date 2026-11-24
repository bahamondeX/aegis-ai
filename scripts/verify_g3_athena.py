"""Check G3's additional query shapes against the authorized G2 lake."""

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from backend.models import Edge, Exposure, Filters, RiskSummary, Vulnerability
from backend.reader import SnapshotReader, View
from infra.operations import stack_outputs
from infra.settings import SCAN_CUTOFF, SDK_CONFIG, Settings
from pipelines.athena import AthenaReader
from pipelines.cloud import SnapshotStore
from pipelines.config import configured_snapshot, project_environment

MAX_QUERIES = 8
QUERY_ALLOWANCE = Decimal(MAX_QUERIES * SCAN_CUTOFF) * Decimal(5) / Decimal(10**12)
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
    environment = project_environment()
    settings = Settings.load(environment=environment)
    ceiling = settings.authorize()
    if OPERATING_ESTIMATE + QUERY_ALLOWANCE > ceiling:
        raise SystemExit("G2 estimate and bounded query allowance exceed the G2 ceiling")
    session, _ = settings.identity()
    outputs = stack_outputs(session, settings)
    client = session.client("athena", config=SDK_CONFIG)
    config = client.get_work_group(WorkGroup=outputs["Workgroup"])["WorkGroup"]["Configuration"]
    if (
        not config["EnforceWorkGroupConfiguration"]
        or config["BytesScannedCutoffPerQuery"] != SCAN_CUTOFF
    ):
        raise SystemExit("G2 Athena workgroup cost controls differ")

    store = SnapshotStore(session.client("s3", config=SDK_CONFIG), outputs["LakeBucket"])
    snapshot = configured_snapshot(environment)
    release = store.release(snapshot)
    if snapshot is None or release is None:
        raise SystemExit("Both local and cloud pinned snapshots are required")
    local = SnapshotReader.duckdb(Path(environment.get("AEGIS_DATA_DIR") or "data"), snapshot)
    stats: list[dict[str, Any]] = []

    class BoundedReader(AthenaReader):
        def _select(
            self, sql: str, *, max_rows: int
        ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
            if len(stats) >= MAX_QUERIES:
                raise RuntimeError("G3 parity query cap reached")
            records, metric = super()._select(sql, max_rows=max_rows)
            stats.append(metric)
            print(json.dumps(metric), flush=True)
            return records, metric

    remote = SnapshotReader.cloud(
        BoundedReader(client, settings.database, outputs["Workgroup"]),
        release,
        geo_available=local.geo_available,
    )
    first = local.vulnerabilities(Filters(limit=1)).data[0]
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
                "worst_case_query_usd": str(QUERY_ALLOWANCE),
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
