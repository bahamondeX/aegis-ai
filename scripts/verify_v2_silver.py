"""Publish and verify the two-date EPSS staging component in AWS Glue and Athena."""

import argparse
import json
import tempfile
from datetime import date
from decimal import Decimal
from pathlib import Path

import pyarrow.compute as pc
from botocore.exceptions import ClientError
from pyiceberg.catalog.glue import GlueCatalog
from pyiceberg.expressions import EqualTo

from infra.operations import stack_outputs
from infra.settings import SCAN_CUTOFF, SDK_CONFIG
from pipelines.athena import AthenaReader
from pipelines.bronze import PREFIX, artifact, ensure, put_record, record
from pipelines.bronze_migrate import verified_lake
from pipelines.config import project_environment
from pipelines.epss_bronze import plan_id, plan_key
from pipelines.io import DataError, write_json
from pipelines.v2_history import NAME, init_table, publish_component, publish_daily_rollup
from scripts.v2_epss_campaign import scope

ALLOCATION = Decimal("0.15")


def verify(canary: dict, attempt: int) -> dict:
    identity = canary["plan"]
    env = project_environment()
    settings = scope(env)
    expected = f"{settings.account}/{settings.region}/{settings.project}/epss-plan/{identity}"
    if (
        canary.get("state") != "passed"
        or env.get("AEGIS_V2_EPSS_PLAN_APPROVAL") != expected
        or not Decimal("0.85") <= Decimal(env.get("AEGIS_V2_ONE_TIME_BUDGET_USD", "0")) <= 15
    ):
        raise DataError("Silver probe requires the verified canary and authorized one-time scope")

    store = verified_lake(settings)
    plan = record(store, plan_key(identity))
    if (
        not plan
        or plan_id(plan) != identity
        or list(plan["members"]) != ["2026-11-20", "2026-11-21"]
    ):
        raise DataError("Silver probe exceeds its two-date scope")
    prefix = f"{PREFIX}/manifests/epss-silver-verification/{identity}"
    if prior := record(store, f"{prefix}/committed.json"):
        return prior

    session, _ = settings.identity()
    outputs = stack_outputs(session, settings)
    athena = session.client("athena", config=SDK_CONFIG)
    group = athena.get_work_group(WorkGroup=settings.project)["WorkGroup"]
    config = group["Configuration"]
    if (
        group["State"] != "ENABLED"
        or not config["EnforceWorkGroupConfiguration"]
        or not 0 < config["BytesScannedCutoffPerQuery"] <= SCAN_CUTOFF
        or config["ResultConfiguration"]["EncryptionConfiguration"]
        != {"EncryptionOption": "SSE_KMS", "KmsKey": outputs["KmsKey"]}
    ):
        raise DataError("verify the existing Athena scan and encryption guards")
    db = settings.database
    if not put_record(
        store,
        f"{prefix}/attempt-{attempt}.json",
        {"two_day_plan": identity, "max_athena_queries": 3, "reserved_usd": str(ALLOCATION)},
        exact=False,
    ):
        raise DataError("Silver attempt was already reserved")
    credentials = session.get_credentials().get_frozen_credentials()
    catalog = GlueCatalog(
        "aegis",
        client=session.client("glue", config=SDK_CONFIG),
        **{
            "s3.region": settings.region,
            "s3.connect-timeout": "5",
            "s3.request-timeout": "30",
            "s3.access-key-id": credentials.access_key,
            "s3.secret-access-key": credentials.secret_key,
            "s3.session-token": credentials.token,
        },
    )
    table = init_table(catalog, f"s3://{store.bucket}/v2/silver", namespace=db)
    release = publish_component(table, store, identity)
    replay = publish_component(table, store, identity)
    if replay["snapshot_id"] != release["snapshot_id"] or not replay["reused"]:
        raise DataError("Silver replay advanced the pinned component")
    probe = AthenaReader(athena, db, settings.project)
    column = '"score_date"'
    rel = f'"{db}"."{NAME}" FOR VERSION AS OF {release["snapshot_id"]}'
    threshold_counts = {}
    for day in plan["members"]:
        scores = (
            table.scan(
                snapshot_id=release["snapshot_id"],
                row_filter=EqualTo("score_date", date.fromisoformat(day)),
                selected_fields=("epss",),
            )
            .to_arrow()["epss"]
        )
        threshold_counts[day] = pc.sum(pc.greater_equal(scores, 0.95)).as_py() or 0
    checks = []
    for selected in (list(plan["members"]), ["2026-11-20"], ["2026-11-21"]):
        dates = ", ".join(f"DATE '{day}'" for day in selected)
        rows, metrics = probe._select(
            f"SELECT {column}, count(*) AS records, count_if(epss >= 0.95) AS high FROM {rel} "
            f"WHERE {column} IN ({dates}) GROUP BY 1 ORDER BY 1",
            max_rows=len(selected),
        )
        expected_counts = {day: release["days"][day] for day in selected}
        if (
            {row["score_date"].isoformat(): row["records"] for row in rows} != expected_counts
            or {row["score_date"].isoformat(): row["high"] for row in rows}
            != {day: threshold_counts[day] for day in selected}
        ):
            raise DataError("Athena and DuckDB date counts differ on the pinned Silver snapshot")
        checks.append({"dates": expected_counts, **metrics})
    if not max(x["scanned_bytes"] for x in checks[1:]) < checks[0]["scanned_bytes"]:
        raise DataError("Athena did not demonstrate date partition pruning")
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        mart = publish_daily_rollup(table, release, root)
        projection = root / "gold" / "epss_daily" / release["component"] / "daily.parquet"
        reference, _ = ensure(store, artifact("epss", "gold", projection), projection)
    result = {
        "state": "passed",
        "visibility": "staging",
        "database": db,
        "table": NAME,
        "table_version": table.format_version,
        "snapshot": release["snapshot_id"],
        "component": release["component"],
        "rows": release["rows"],
        "replay": replay["reused"],
        "athena": checks,
        "gold": {**mart, "key": reference.key, "version": reference.version_id},
    }
    put_record(store, f"{prefix}/committed.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--attempt", type=int, choices=(1, 2, 3), default=1)
    args = parser.parse_args()
    result = verify(json.loads((args.evidence / "canary.json").read_bytes()), args.attempt)
    write_json(args.evidence / "silver.json", result)
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except ClientError as error:
        raise SystemExit(
            f"Silver verification AWS error: {error.response['Error']['Code']}"
        ) from None
    except (DataError, OSError, ValueError, KeyError) as error:
        raise SystemExit(f"Silver verification failed: {error}") from None
