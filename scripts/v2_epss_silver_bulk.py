"""Attach verified EPSS Parquet partitions to Iceberg and build the daily Gold mart."""

import argparse
import json
import tempfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
from botocore.exceptions import ClientError
from pyiceberg.table import Table

from infra.operations import scoped_catalog, stack_outputs
from infra.settings import SCAN_CUTOFF, SDK_CONFIG
from pipelines.athena import AthenaReader
from pipelines.bronze import PREFIX, ObjectRef, S3Bronze, artifact, ensure, put_record, record
from pipelines.bronze_migrate import verified_lake
from pipelines.config import project_environment
from pipelines.epss_bronze import campaign_key, day_key, plan_id
from pipelines.io import DataError, write_json
from pipelines.v2_history import NAME
from scripts.v2_epss_campaign import authorized, scope

CANARY_DATES = {"2026-11-20", "2026-11-21"}
MAX_QUERY_DAYS = 16
ALLOCATION = Decimal("0.75")
PREVIOUS_STAGING = Decimal("0.45")


def read_ledger(store: S3Bronze, members: dict, *, probe: str | None) -> dict:
    def load(day: str) -> dict:
        member = members[day]
        receipt = record(store, day_key(day, member["sha"]))
        if (
            not receipt
            or receipt["score_date"] != day
            or receipt["upstream_git_blob_sha1"] != member["sha"]
        ):
            raise DataError(f"EPSS Bronze date {day} has no verified receipt")
        for name in ("normalized_object", "raw_object"):
            ref = ObjectRef(**receipt[name])
            if ref.key.split("/")[2:4] != ["epss", name.removesuffix("_object")]:
                raise DataError("EPSS date points outside the authorized data prefix")
        ref = ObjectRef(**receipt["normalized_object"])
        if store.inspect(ref.key) != ref or receipt["counts"]["valid"] < 1:
            raise DataError("EPSS normalized data has changed since Bronze verified it")
        return receipt

    with ThreadPoolExecutor(max_workers=8) as workers:
        selected = [probe] if probe else sorted(members)
        return dict(zip(selected, workers.map(load, selected), strict=True))


def file_days(table: Table) -> dict[str, list[str]]:
    dates = defaultdict(list)
    epoch = date(1970, 1, 1)
    for task in table.scan().plan_files():
        (day,) = tuple(task.file.partition)
        dates[(epoch + timedelta(days=day)).isoformat()].append(task.file.file_path)
    return dict(dates)


def attach(table: Table, bucket: str, ledger: dict, windows: list[dict]) -> int:
    if table.schema().find_field("evidence_key").required:
        table.update_schema().make_column_optional("evidence_key").commit()
    if table.properties.get("gc.enabled") != "false":
        with table.transaction() as tx:
            tx.set_properties(**{"gc.enabled": "false"})
    current = file_days(table)
    written = 0
    for window in windows:
        files = []
        dates = []
        for day in sorted(window["members"].keys() & ledger.keys()):
            path = f"s3://{bucket}/{ledger[day]['normalized_object']['key']}"
            if paths := current.get(day):
                if paths != [path] and day not in CANARY_DATES:
                    raise DataError(f"Silver date {day} is already bound to a different file")
            else:
                files.append(path)
                dates.append(day)
        if files:
            table.add_files(files, snapshot_properties={"aegis.epss-window": plan_id(window)})
            written += len(files)
            print(
                json.dumps(
                    {"attached_dates": dates, "snapshot": table.current_snapshot().snapshot_id}
                ),
                flush=True,
            )
    return written


def gold(table: Table, reader: AthenaReader, store: S3Bronze, ledger: dict, *, probe: bool) -> dict:
    snapshot = table.current_snapshot().snapshot_id
    db = reader.database
    rel = f'"{db}"."{NAME}" FOR VERSION AS OF {snapshot}'
    all_days = sorted(ledger)
    observations, queries = [], []
    for start in range(0, len(all_days), MAX_QUERY_DAYS):
        dates = all_days[start : start + MAX_QUERY_DAYS]
        selected = ", ".join(f"DATE '{date.fromisoformat(day).isoformat()}'" for day in dates)
        rows, metrics = reader._select(
            f"""SELECT score_date, min(model_version) AS model_version,
                      count(DISTINCT model_version) AS model_count, count(*) AS observed_count,
                      count_if(percentile IS NULL) AS missing_percentile_count,
                      count_if(epss >= 0.95) AS probability_at_least_095_count,
                      avg(epss) AS mean_probability,
                      approx_percentile(epss, 0.5) AS approximate_median_probability,
                      approx_percentile(epss, 0.95) AS approximate_p95_probability
                 FROM {rel} WHERE score_date IN ({selected}) GROUP BY 1 ORDER BY 1""",
            max_rows=len(dates),
        )
        if len(rows) != len(dates):
            raise DataError("the Gold query omitted a verified source date")
        for day, row in zip(dates, rows, strict=True):
            receipt = ledger[day]
            if (
                row["score_date"].isoformat() != day
                or row.pop("model_count") != 1
                or row["model_version"] != receipt["model_version"]
                or row["observed_count"] != receipt["counts"]["valid"]
                or row["missing_percentile_count"] != receipt["counts"]["missing_percentile"]
            ):
                raise DataError(f"Gold daily counts for {day} differ from the verified Bronze data")
        observations.extend(rows)
        queries.append(metrics)
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "daily.parquet"
        pq.write_table(pa.Table.from_pylist(observations), path, compression="zstd")
        ref, _ = ensure(store, artifact("epss", "gold", path), path)
    return {
        "snapshot": snapshot,
        "dates": len(ledger),
        "rows": sum(i["counts"]["valid"] for i in ledger.values()),
        "mart_version": ref.version_id,
        "mart_key": ref.key,
        "mart_sha256": ref.sha256,
        "mart_bytes": ref.size,
        "probe": probe,
        "athena": queries,
        "coverage_start": all_days[0],
        "coverage_end": all_days[-1],
    }


def publish(bundle: dict, probe: str | None, attempt: int) -> dict:
    env = project_environment()
    settings = scope(env)
    authorized(env, settings, bundle)
    initial = sum(
        Decimal(env.get(key, "0"))
        for key in ("AEGIS_V2_MIGRATION_USD", "AEGIS_V2_EPSS_PLAN_USD", "AEGIS_V2_HISTORY_USD")
    )
    if initial + PREVIOUS_STAGING + ALLOCATION > Decimal(env["AEGIS_V2_ONE_TIME_BUDGET_USD"]):
        raise DataError("bulk EPSS publication exceeds its one-time allocation")
    store = verified_lake(settings)
    campaign, spec = bundle["campaign"], bundle["spec"]
    if record(store, campaign_key(campaign)) != spec:
        raise DataError("the reviewed campaign is not committed in Bronze")
    stage = f"{PREFIX}/manifests/epss-silver-verification/{campaign}/{probe or 'full'}"
    if committed := record(store, f"{stage}/committed.json"):
        return committed
    if probe and (probe in CANARY_DATES or probe != "2021-05-14"):
        raise DataError("the approved external-file probe is restricted to 2021-05-14")
    session, _ = settings.identity()
    outputs = stack_outputs(session, settings)
    athena = session.client("athena", config=SDK_CONFIG)
    group = athena.get_work_group(WorkGroup=settings.project)["WorkGroup"]
    conf = group["Configuration"]
    if (
        group["State"] != "ENABLED"
        or not conf["EnforceWorkGroupConfiguration"]
        or not 0 < conf["BytesScannedCutoffPerQuery"] <= SCAN_CUTOFF
        or conf["ResultConfiguration"]["EncryptionConfiguration"]
        != {"EncryptionOption": "SSE_KMS", "KmsKey": outputs["KmsKey"]}
    ):
        raise DataError("bulk EPSS publication requires the approved Athena workgroup")
    windows = sorted(bundle["plans"].values(), key=lambda x: x["start"])
    members = {day: info for window in windows for day, info in window["members"].items()}
    if len(members) != spec["official_days"]:
        raise DataError("historical roster does not match the reviewed completeness denominator")
    ledger = read_ledger(store, members, probe=probe)
    queries = (len(ledger) + MAX_QUERY_DAYS - 1) // MAX_QUERY_DAYS
    if queries > 132 or not put_record(
        store,
        f"{stage}/attempt-{attempt}.json",
        {"max_queries": queries, "usd": str(ALLOCATION)},
        exact=False,
    ):
        raise DataError("bulk EPSS publication has no remaining attempt reservation")
    table = scoped_catalog(session, settings).load_table((settings.database, NAME))
    expected_path = f"s3://{store.bucket}/v2/silver/{settings.database}/{NAME}"
    if table.format_version != 2 or table.location() != expected_path:
        raise DataError("bulk publication targets a different Iceberg table")
    attached = attach(table, store.bucket, ledger, windows)
    if attach(table, store.bucket, ledger, windows):
        raise DataError("bulk EPSS publication duplicated a committed date")
    result = gold(
        table,
        AthenaReader(athena, settings.database, settings.project),
        store,
        ledger,
        probe=bool(probe),
    )
    result.update(
        {
            "state": "passed",
            "new_partitions": attached,
            "table_version": 2,
            "campaign": campaign,
            "archive_absent_days": spec["archive_absent_days"],
            "date_evidence": {day: item["raw_object"] for day, item in ledger.items()},
        }
    )
    put_record(store, f"{stage}/committed.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--probe-date", type=date.fromisoformat)
    parser.add_argument("--attempt", default=1, type=int, choices=(1, 2, 3))
    args = parser.parse_args()
    day = args.probe_date.isoformat() if args.probe_date else None
    result = publish(json.loads(args.bundle.read_bytes()), day, args.attempt)
    write_json(args.evidence / f"bulk-silver-{day or 'full'}.json", result)
    print(json.dumps({k: v for k, v in result.items() if k not in {"date_evidence", "athena"}}))


if __name__ == "__main__":
    try:
        main()
    except ClientError as error:
        raise SystemExit(f"Bulk EPSS AWS error: {error.response['Error']['Code']}") from None
    except (DataError, OSError, ValueError, KeyError) as error:
        raise SystemExit(f"Bulk EPSS publication failed: {error}") from None
