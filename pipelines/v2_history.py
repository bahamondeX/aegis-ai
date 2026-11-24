"""Build and read a version-pinned EPSS Iceberg component for the V2 canary."""

import argparse
import json
import statistics
import time
from datetime import date, timedelta
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq
from pyiceberg.catalog import Catalog
from pyiceberg.catalog.sql import SqlCatalog
from pyiceberg.expressions import And, EqualTo, GreaterThanOrEqual, In, LessThanOrEqual
from pyiceberg.partitioning import PartitionField, PartitionSpec
from pyiceberg.schema import assign_fresh_schema_ids
from pyiceberg.table import Table
from pyiceberg.transforms import IdentityTransform

from pipelines.bronze import (
    PREFIX,
    BronzeStore,
    LocalBronze,
    ObjectRef,
    materialized,
    put_record,
    record,
)
from pipelines.bulk_epss import SCHEMA as BRONZE_SCHEMA
from pipelines.bulk_vulnerabilities import RECORD_ID
from pipelines.epss_bronze import plan_id, plan_key, verified_date
from pipelines.io import DataError

NAME = "fact_epss_daily"
NAMESPACE = "aegis_v2_pilot"
SCHEMA = BRONZE_SCHEMA.append(pa.field("evidence_key", pa.string(), nullable=False))


def init_table(catalog: Catalog, warehouse: str) -> Table:
    schema = assign_fresh_schema_ids(Catalog._convert_schema_if_needed(SCHEMA))
    partition = PartitionSpec(
        PartitionField(
            schema.find_field("score_date").field_id, 1000, IdentityTransform(), "score_date"
        ),
    )
    location = f"{warehouse}/{NAMESPACE}/{NAME}"
    table = catalog.create_table_if_not_exists(
        (NAMESPACE, NAME),
        schema,
        location=location,
        partition_spec=partition,
        properties={
            "format-version": "2",
            "write.parquet.compression-codec": "zstd",
            "write.target-file-size-bytes": str(64 * 1024**2),
            "write.parquet.row-group-limit": "65536",
        },
    )
    if (
        table.format_version != 2
        or table.location() != location
        or table.spec() != partition
        or table.schema().as_struct() != schema.as_struct()
    ):
        raise DataError("existing EPSS Silver table differs from its reviewed schema")
    return table


def component_key(identity: str) -> str:
    return f"{PREFIX}/manifests/epss-components/{identity}.json"


def check_member(rows: pa.Table, receipt: dict, score_day: date) -> None:
    cves = rows["cve_id"]
    if (
        rows.num_rows != receipt["counts"]["valid"]
        or pc.count_distinct(cves).as_py() != rows.num_rows
        or pc.count_distinct(rows["score_date"]).as_py() != 1
        or pc.count_distinct(rows["model_version"]).as_py() != 1
        or rows["score_date"][0].as_py() != score_day
        or rows["model_version"][0].as_py() != receipt["model_version"]
    ):
        raise DataError("EPSS source grain differs from its verified date receipt")


def publish_component(table: Table, store: BronzeStore, identity: str) -> dict:
    plan = record(store, plan_key(identity))
    if not plan or plan_id(plan) != identity or not plan["members"]:
        raise DataError("no complete reviewed EPSS plan for Silver")
    days = {}
    for day, member in sorted(plan["members"].items()):
        receipt = verified_date(store, day, member["sha"])
        if receipt is None:
            raise DataError(f"planned EPSS date {day} is still pending")
        days[day] = receipt
    table_id = str(table.metadata.table_uuid)
    component = plan_id(
        {
            "plan": identity,
            "table_uuid": table_id,
            "normalized": {day: value["normalized_object"] for day, value in days.items()},
        }
    )
    key = component_key(component)
    if previous := record(store, key):
        if table.snapshot_by_id(previous["snapshot_id"]) is None:
            raise DataError("component snapshot is no longer available")
        return {**previous, "reused": True}
    total = 0
    written = 0
    for day, receipt in days.items():
        score_day = date.fromisoformat(day)
        ref = ObjectRef(**receipt["normalized_object"])
        evidence = receipt["raw_object"]["key"]
        filter_day = EqualTo("score_date", score_day)
        prior = table.scan(
            row_filter=filter_day,
            selected_fields=("evidence_key",),
        ).to_arrow()
        with materialized(store, ref) as file:
            data = pq.read_table(file)
            check_member(data, receipt, score_day)
        if prior.num_rows != data.num_rows or pc.unique(prior["evidence_key"]).to_pylist() != [
            evidence
        ]:
            data = data.sort_by("cve_id")
            data = data.append_column(
                SCHEMA.field("evidence_key"), pa.array([evidence] * data.num_rows, type=pa.string())
            )
            if prior.num_rows:
                table.overwrite(data, overwrite_filter=filter_day)
            else:
                table.append(data)
            written += 1
        total += data.num_rows
    snapshot = table.current_snapshot()
    if snapshot is None:
        raise DataError("no Silver snapshot after processing the EPSS component")
    pinned = table.scan(
        row_filter=In("score_date", [date.fromisoformat(day) for day in days]),
        snapshot_id=snapshot.snapshot_id,
        selected_fields=("score_date",),
    )
    expected = dict(sorted((day, item["counts"]["valid"]) for day, item in days.items()))
    with duckdb.connect(config={"threads": "2", "memory_limit": "256MB"}) as db:
        # Read only the partition/date field. The actual rows stay in the Iceberg files.
        db.register("dates", pinned.to_arrow_batch_reader())
        count_rows = db.sql("SELECT score_date, count(*) FROM dates GROUP BY 1").fetchall()
    actual = {day.isoformat(): count for day, count in count_rows if day.isoformat() in days}
    if actual != expected:
        raise DataError("Iceberg date counts do not reconcile with Bronze")
    manifest = {
        "component": component,
        "schema_version": 1,
        "plan": identity,
        "table_uuid": table_id,
        "snapshot_id": snapshot.snapshot_id,
        "start": plan["start"],
        "end": plan["end"],
        "days": expected,
        "rows": total,
    }
    put_record(store, key, manifest)
    return {**manifest, "written_days": written, "reused": False}


def temporal_rows(
    observations: list[dict],
    start: date,
    end: date,
    included: set[str],
) -> list[dict]:
    by_day = {row["score_date"]: row for row in observations}
    result = []
    for offset in range((end - start).days + 1):
        day = start + timedelta(days=offset)
        row = by_day.get(day)
        view: dict = {
            "score_date": day.isoformat(),
            "status": "source_absent" if day.isoformat() not in included else "cve_unscored",
        }
        if row is not None:
            view.update(row, score_date=day.isoformat(), status="observed")
            previous = by_day.get(day - timedelta(days=1))
            view["model_transition"] = bool(
                previous and previous["model_version"] != row["model_version"]
            )
            for window in (1, 7, 30):
                baseline = by_day.get(day - timedelta(days=window))
                view[f"change_{window}d"] = (
                    row["epss"] - baseline["epss"]
                    if baseline is not None and baseline["model_version"] == row["model_version"]
                    else None
                )
                if window == 1:
                    continue
                span = [by_day.get(day - timedelta(days=back)) for back in range(window)]
                values = [
                    p["epss"] for p in span if p and p["model_version"] == row["model_version"]
                ]
                view[f"mean_{window}d"] = (
                    statistics.fmean(values) if len(values) == window else None
                )
                view[f"volatility_{window}d"] = (
                    statistics.pstdev(values) if len(values) == window else None
                )
        result.append(view)
    return result


def history(table: Table, release: dict, cve: str, start: date, end: date) -> dict:
    if (
        not RECORD_ID.fullmatch(cve)
        or not 0 <= (end - start).days < 366
        or str(table.metadata.table_uuid) != release["table_uuid"]
        or table.snapshot_by_id(release["snapshot_id"]) is None
        or not date.fromisoformat(release["start"])
        <= start
        <= end
        <= date.fromisoformat(release["end"])
    ):
        raise DataError("invalid CVE, table identity or date range for the pinned component")
    started = time.monotonic()
    scan_start = max(date.fromisoformat(release["start"]), start - timedelta(days=30))
    rows = (
        table.scan(
            row_filter=And(
                EqualTo("cve_id", cve),
                GreaterThanOrEqual("score_date", scan_start),
                LessThanOrEqual("score_date", end),
            ),
            snapshot_id=release["snapshot_id"],
        )
        .to_arrow()
        .to_pylist()
    )
    # A later or neighboring component may keep more dates in the same table snapshot.
    dates = set(release["days"])
    return {
        "component": release["component"],
        "snapshot_id": release["snapshot_id"],
        "cve_id": cve,
        "unit": "probability",
        "granularity": "day",
        "observations": temporal_rows(
            [row for row in rows if row["score_date"].isoformat() in dates],
            start,
            end,
            dates,
        ),
        "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-store", type=Path, required=True)
    parser.add_argument("--warehouse", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    publish = commands.add_parser("publish")
    publish.add_argument("--plan", required=True)
    read = commands.add_parser("history")
    read.add_argument("--component", required=True)
    read.add_argument("--cve", required=True)
    read.add_argument("--start", type=date.fromisoformat, required=True)
    read.add_argument("--end", type=date.fromisoformat, required=True)
    args = parser.parse_args()
    root = args.warehouse.resolve()
    root.mkdir(parents=True, exist_ok=True)
    warehouse = (root / "iceberg").as_uri()
    catalog = SqlCatalog("v2_history", uri=f"sqlite:///{root / 'catalog.db'}", warehouse=warehouse)
    catalog.create_namespace_if_not_exists(NAMESPACE)
    store = LocalBronze(args.local_store)
    if args.command == "publish":
        output = publish_component(init_table(catalog, warehouse), store, args.plan)
    else:
        release = record(store, component_key(args.component))
        if release is None:
            raise DataError("EPSS component manifest is unavailable")
        output = history(
            catalog.load_table((NAMESPACE, NAME)), release, args.cve, args.start, args.end
        )
    print(json.dumps(output, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (DataError, OSError, ValueError, KeyError) as error:
        raise SystemExit(f"V2 EPSS analytical component failed: {error}") from None
