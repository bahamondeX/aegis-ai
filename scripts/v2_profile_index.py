"""Index every CVE source revision to an exact, versioned Parquet row group."""

import argparse
import json
import tempfile
from collections import defaultdict
from contextlib import ExitStack
from dataclasses import asdict
from decimal import Decimal
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
from botocore.exceptions import ClientError

from backend.v2_profiles import INDEX_PREFIX, ROW_GROUP_LIMIT, ProfileBudget, VersionedRanges
from pipelines.bronze import PREFIX, ObjectRef, artifact, ensure, put_record, record
from pipelines.bronze_migrate import verified_lake
from pipelines.config import project_environment
from pipelines.epss_bronze import HEX, plan_id
from pipelines.io import DataError, file_digest, write_json
from scripts.v2_catalog_silver import COUNTS
from scripts.v2_epss_campaign import scope

ALLOCATION = Decimal("0.25")
PREVIOUS_STAGING = Decimal("1.60")
LOCATOR = pa.schema(
    [
        pa.field("cve_id", pa.string(), nullable=False),
        pa.field(
            "locations",
            pa.list_(
                pa.struct(
                    [
                        pa.field("capture", pa.string(), nullable=False),
                        pa.field("row_group", pa.int16(), nullable=False),
                    ]
                )
            ),
            nullable=False,
        ),
    ]
)


def publish(inventory: str, attempt: int, cache: Path) -> dict:
    env = project_environment()
    settings = scope(env)
    expected = (
        f"{settings.account}/{settings.region}/{settings.project}/bronze-migration/{inventory}"
    )
    charge = (
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
        or not charge <= Decimal(env.get("AEGIS_V2_ONE_TIME_BUDGET_USD", "0")) <= 15
    ):
        raise DataError("profile index requires the verified inventory and its one-time allocation")
    store = verified_lake(settings)
    staged = record(store, f"{PREFIX}/manifests/cve-catalog-stage/{inventory}/committed.json")
    migration = record(store, f"{PREFIX}/manifests/migrations/{inventory}/committed.json")
    if not staged or not migration or staged["inventory"] != inventory:
        raise DataError("the committed catalog stage is unavailable")
    component = staged["component"]
    prefix = f"{INDEX_PREFIX}/{component}"
    if previous := record(store, prefix + "/committed.json"):
        return previous
    refs = {row["key"]: row for row in migration["objects"]}
    normalized = {}
    for item in migration["inventory"]:
        name = Path(item["name"])
        if name.parts[0] == "vulnerabilities" and name.name == "records.parquet":
            capture = "/".join(name.parts[1:3])
            normalized[capture] = (name, refs[item["key"]])
    if set(normalized) != set(staged["evidence"]) or len(normalized) != 29:
        raise DataError("profile index capture coverage differs from verified Silver")
    if not put_record(
        store,
        prefix + f"/attempt-{attempt}.json",
        {"capture_count": len(normalized), "usd": str(ALLOCATION)},
        exact=False,
    ):
        raise DataError("profile index attempt was already reserved")
    sources: defaultdict[str, int] = defaultdict(int)
    index: dict = {
        "schema_version": 1,
        "inventory": inventory,
        "catalog_component": component,
        "sources": {key: value for key, (_, value) in normalized.items()},
        "years": {},
    }
    with ExitStack() as resources:
        files = {}
        groups: defaultdict[str, list[tuple[str, int]]] = defaultdict(list)
        for capture, (path, value) in normalized.items():
            if staged["evidence"][capture] != value:
                raise DataError(
                    "profile source reference differs from the reviewed Silver evidence"
                )
            ref = ObjectRef(**value)
            if store.inspect(ref.key) != ref:
                raise DataError("a profile source artifact changed since migration")
            local = cache / path
            if (
                local.is_file()
                and local.stat().st_size == ref.size
                and file_digest(local) == ref.sha256
            ):
                parquet = pq.ParquetFile(local)
            else:
                budget = ProfileBudget(byte_limit=64 * 1024**2, request_limit=1200)
                stream = resources.enter_context(VersionedRanges(store, ref, budget))
                parquet = pq.ParquetFile(stream)
            if (
                not 0 < parquet.num_row_groups <= ROW_GROUP_LIMIT
                or parquet.metadata.num_rows > 450_000
            ):
                raise DataError("profile artifact exceeds its verified row group or record limit")
            files[capture] = parquet
            for row_group in range(parquet.num_row_groups):
                stats = parquet.metadata.row_group(row_group).column(0).statistics
                if not stats or not stats.has_min_max:
                    raise DataError("profile index requires CVE ID range statistics")
                first, last = int(stats.min[4:8]), int(stats.max[4:8])
                if not 1990 <= first <= last <= 2100:
                    raise DataError("profile source contains an invalid CVE year bound")
                for year_number in range(first, last + 1):
                    groups[str(year_number)].append((capture, row_group))
        path = Path(resources.enter_context(tempfile.TemporaryDirectory())) / "locations.parquet"
        for year, candidates in sorted(groups.items()):
            rows: defaultdict[str, list[dict]] = defaultdict(list)
            for capture, row_group in candidates:
                ids = files[capture].read_row_group(row_group, columns=["cve_id"])["cve_id"]
                for cve in ids.to_pylist():
                    if cve[4:8] == year:
                        rows[cve].append({"capture": capture, "row_group": row_group})
                        sources[capture.split("/")[0]] += 1
            if not rows:
                continue
            table = pa.Table.from_pylist(
                [{"cve_id": cve, "locations": values} for cve, values in sorted(rows.items())],
                schema=LOCATOR,
            )
            pq.write_table(table, path, compression="zstd", row_group_size=4096)
            ref, _ = ensure(store, artifact("vulnerabilities", "profile-index", path), path)
            index["years"][year] = {"count": len(rows), "object": asdict(ref)}
            print(json.dumps({"year": year, "profiles": len(rows), "bytes": ref.size}), flush=True)
    if dict(sources) != {key: counts[0] for key, counts in COUNTS.items()}:
        raise DataError("profile index source totals differ from Bronze and Silver")
    index["source_records"] = sum(sources.values())
    index["distinct_cves"] = sum(row["count"] for row in index["years"].values())
    if index["distinct_cves"] != staged["distinct_cves"]:
        raise DataError("profile index and verified catalog CVE totals differ")
    result = {"state": "passed", "index_id": plan_id(index), "manifest": index}
    put_record(store, prefix + "/committed.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--attempt", type=int, choices=(1, 2, 3), default=1)
    parser.add_argument("--cache", type=Path, default=Path("data/v2"))
    args = parser.parse_args()
    result = publish(args.inventory, args.attempt, args.cache)
    write_json(args.output, result)
    print(
        json.dumps(
            {
                "index_id": result["index_id"],
                "distinct_cves": result["manifest"]["distinct_cves"],
                "source_records": result["manifest"]["source_records"],
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except ClientError as error:
        raise SystemExit(f"Profile index AWS error: {error.response['Error']['Code']}") from None
    except (DataError, OSError, ValueError, KeyError) as error:
        raise SystemExit(f"Profile index failed: {error}") from None
