"""Build year-sharded, release-pinned catalog pages from the verified Iceberg index."""

import argparse
import json
import tempfile
import time
from collections.abc import Iterator
from dataclasses import asdict
from decimal import Decimal
from pathlib import Path

import duckdb
import pyarrow.parquet as pq
from botocore.exceptions import ClientError

from backend.v2_catalog import GOLD_PREFIX
from infra.operations import scoped_catalog
from pipelines.bronze import PREFIX, artifact, ensure, put_record, record
from pipelines.bronze_migrate import verified_lake
from pipelines.config import project_environment
from pipelines.epss_bronze import HEX, plan_id
from pipelines.io import DataError, write_json
from scripts.v2_catalog_silver import NAME
from scripts.v2_epss_campaign import scope

ALLOCATION = Decimal("0.25")
PREVIOUS_STAGING = Decimal("1.35")


def shards(connection: duckdb.DuckDBPyConnection, folder: Path) -> Iterator[tuple[int, int, Path]]:
    connection.execute("""
        CREATE TEMP TABLE catalog AS
        SELECT cve_id, substring(cve_id, 5, 4)::integer AS year,
               min(published_at) AS earliest_publication,
               max(modified_at) AS latest_modification,
               bool_or(source = 'kev') AS in_kev,
               bool_or(coalesce(has_cvss, false)) AS has_cvss,
               bool_or(coalesce(has_cwe, false)) AS has_cwe,
               bool_or(coalesce(has_cpe, false)) AS has_cpe,
               bool_or(coalesce(has_ssvc, false)) AS has_ssvc,
               list(DISTINCT source ORDER BY source) AS sources
          FROM source_captures GROUP BY 1, 2
    """)
    totals = connection.execute(
        "SELECT year, count(*) FROM catalog GROUP BY 1 ORDER BY 1"
    ).fetchall()
    if len(totals) > 100:
        raise DataError("catalog year index exceeds its serving budget")
    for year, count in totals:
        if not 1990 <= year <= 2100 or not 0 < count <= 100_000:
            raise DataError("catalog shard exceeds the reviewed year or row budget")
        path = folder / f"catalog-{year}.parquet"
        data = connection.execute(
            "SELECT * FROM catalog WHERE year=? ORDER BY cve_id", [year]
        ).to_arrow_table()
        if data.num_rows != count:
            raise DataError("materialized catalog shard has the wrong denominator")
        pq.write_table(data, path, compression="zstd", row_group_size=4096)
        if path.stat().st_size > 8 * 1024**2:
            raise DataError("catalog Parquet shard exceeds its serving byte budget")
        yield year, count, path
        path.unlink()


def publish(inventory: str, attempt: int) -> dict:
    started = time.monotonic()
    env = project_environment()
    settings = scope(env)
    expected = (
        f"{settings.account}/{settings.region}/{settings.project}/bronze-migration/{inventory}"
    )
    reserved = (
        sum(
            Decimal(env.get(key, "0"))
            for key in ("AEGIS_V2_MIGRATION_USD", "AEGIS_V2_EPSS_PLAN_USD", "AEGIS_V2_HISTORY_USD")
        )
        + PREVIOUS_STAGING
        + ALLOCATION
    )
    if (
        not HEX.fullmatch(inventory)
        or env.get("AEGIS_V2_MIGRATION_APPROVAL") != expected
        or not reserved <= Decimal(env.get("AEGIS_V2_ONE_TIME_BUDGET_USD", "0")) <= 15
    ):
        raise DataError("Gold catalog requires the verified inventory and its one-time allocation")
    store = verified_lake(settings)
    stage = record(store, f"{PREFIX}/manifests/cve-catalog-stage/{inventory}/committed.json")
    if not stage or stage["table"] != NAME or stage["inventory"] != inventory:
        raise DataError("catalog Silver snapshot is unavailable")
    identity = stage["component"]
    previous = record(store, f"{GOLD_PREFIX}/{identity}/committed.json")
    if previous:
        if plan_id(previous["manifest"]) != previous["release_id"]:
            raise DataError("committed catalog digest has changed")
        return previous
    if not put_record(
        store,
        f"{GOLD_PREFIX}/{identity}/attempt-{attempt}.json",
        {"usd": str(ALLOCATION)},
        exact=False,
    ):
        raise DataError("catalog Gold attempt is already reserved")
    session, _ = settings.identity()
    table = scoped_catalog(session, settings).load_table((settings.database, NAME))
    snapshot = stage["snapshot"]
    if table.format_version != 2 or table.snapshot_by_id(snapshot) is None:
        raise DataError("the reviewed catalog component is no longer available")
    manifest = {
        "schema_version": 1,
        "inventory": inventory,
        "silver_snapshot": snapshot,
        "shards": {},
    }
    with (
        tempfile.TemporaryDirectory() as temporary,
        duckdb.connect(
            config={"threads": "2", "memory_limit": "256MB", "temp_directory": temporary}
        ) as connection,
    ):
        connection.register(
            "source_captures",
            table.scan(
                snapshot_id=snapshot,
                selected_fields=(
                    "cve_id",
                    "published_at",
                    "modified_at",
                    "source",
                    "has_cvss",
                    "has_cwe",
                    "has_cpe",
                    "has_ssvc",
                ),
            ).to_arrow_batch_reader(),
        )
        for year, count, path in shards(connection, Path(temporary)):
            ref, _ = ensure(store, artifact("vulnerabilities", "catalog", path), path)
            manifest["shards"][str(year)] = {"count": count, "object": asdict(ref)}
            print(json.dumps({"year": year, "cves": count, "bytes": ref.size}), flush=True)
    manifest["distinct_cves"] = sum(row["count"] for row in manifest["shards"].values())
    if manifest["distinct_cves"] != stage["distinct_cves"]:
        raise DataError("catalog mart and source-capture CVE totals differ")
    release = plan_id(manifest)
    result = {
        "state": "passed",
        "visibility": "staging",
        "release_id": release,
        "manifest": manifest,
        "bytes": sum(row["object"]["size"] for row in manifest["shards"].values()),
        "seconds": round(time.monotonic() - started, 2),
    }
    put_record(store, f"{GOLD_PREFIX}/{identity}/committed.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--attempt", type=int, default=1, choices=(1, 2, 3))
    args = parser.parse_args()
    result = publish(args.inventory, args.attempt)
    write_json(args.output, result)
    print(json.dumps({k: v for k, v in result.items() if k != "manifest"}))


if __name__ == "__main__":
    try:
        main()
    except ClientError as error:
        raise SystemExit(f"Gold catalog AWS error: {error.response['Error']['Code']}") from None
    except (DataError, OSError, ValueError, KeyError) as error:
        raise SystemExit(f"Gold catalog failed: {error}") from None
