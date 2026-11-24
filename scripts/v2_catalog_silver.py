"""Publish a source-grain vulnerability index from the authorized Bronze inventory."""

import argparse
import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from decimal import Decimal
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq
from botocore.exceptions import ClientError
from pyiceberg.catalog import Catalog
from pyiceberg.catalog.glue import GlueCatalog
from pyiceberg.partitioning import PartitionField, PartitionSpec
from pyiceberg.schema import assign_fresh_schema_ids
from pyiceberg.transforms import IdentityTransform

from infra.operations import stack_outputs
from infra.settings import SCAN_CUTOFF, SDK_CONFIG
from pipelines.athena import AthenaReader
from pipelines.bronze import PREFIX, ObjectRef, S3Bronze, materialized, put_record, record
from pipelines.bronze_migrate import verified_lake
from pipelines.bulk_vulnerabilities import SCHEMA as UPSTREAM
from pipelines.config import project_environment
from pipelines.epss_bronze import HEX, plan_id
from pipelines.io import DataError, file_digest, write_json
from pipelines.lakehouse import athena_timestamps
from scripts.v2_epss_campaign import scope

NAME = "fact_cve_source_capture"
INPUT_FIELDS = tuple(field.name for field in UPSTREAM if field.name != "payload")
SCHEMA = pa.schema(
    [UPSTREAM.field(name) for name in INPUT_FIELDS]
    + [
        pa.field("source", pa.string(), nullable=False),
        pa.field("capture", pa.string(), nullable=False),
        pa.field("source_normalized_sha256", pa.string(), nullable=False),
    ]
)
COUNTS = {"cve": (431604, 431119), "kev": (1792, 1792), "nvd": (440131, 431114)}
CAP = Decimal("0.30")
STAGING_PRIOR = Decimal("0.15")


@contextmanager
def verified_input(store: S3Bronze, ref: ObjectRef, local: Path) -> Iterator[Path]:
    if store.inspect(ref.key) != ref:
        raise DataError("migrated vulnerability artifact differs from its approved version")
    if local.is_file() and local.stat().st_size == ref.size and file_digest(local) == ref.sha256:
        yield local
        return
    with materialized(store, ref) as path:
        yield path


def projection(path: Path, source: str, capture: str, ref: ObjectRef) -> pa.Table:
    artifact = pq.ParquetFile(path)
    rows = artifact.metadata.num_rows
    if not 0 < rows <= 450_000:
        raise DataError("vulnerability capture exceeds the staging row budget")
    table = artifact.read(columns=list(INPUT_FIELDS))
    if table["cve_id"].null_count or pc.count_distinct(table["cve_id"]).as_py() != rows:
        raise DataError("duplicate or missing CVE in a verified capture")
    table = athena_timestamps(table).sort_by("cve_id")
    return pa.Table.from_arrays(
        [*table.columns, *[pa.array([value] * rows) for value in (source, capture, ref.sha256)]],
        schema=SCHEMA,
    )


def publish(identity: str, attempt: int, cache: Path) -> dict:
    env = project_environment()
    settings = scope(env)
    prefix = f"{settings.account}/{settings.region}/{settings.project}/bronze-migration/"
    if (
        not HEX.fullmatch(identity)
        or env.get("AEGIS_V2_MIGRATION_APPROVAL") != prefix + identity
        or sum(
            Decimal(env.get(key, "0"))
            for key in ("AEGIS_V2_MIGRATION_USD", "AEGIS_V2_EPSS_PLAN_USD", "AEGIS_V2_HISTORY_USD")
        )
        + STAGING_PRIOR
        + CAP
        > Decimal(env.get("AEGIS_V2_ONE_TIME_BUDGET_USD", "0"))
    ):
        raise DataError("catalog staging requires the verified inventory and one-time budget")
    store = verified_lake(settings)
    committed = record(store, f"{PREFIX}/manifests/migrations/{identity}/committed.json")
    if not committed or committed["inventory_id"] != identity or len(committed["objects"]) != 572:
        raise DataError("catalog staging requires the complete 572-object inventory")
    stage = f"{PREFIX}/manifests/cve-catalog-stage/{identity}"
    if saved := record(store, f"{stage}/committed.json"):
        return saved
    refs = {item["key"]: ObjectRef(**item) for item in committed["objects"]}
    partitions = []
    for item in committed["inventory"]:
        path = Path(item["name"])
        if path.parts[0] == "vulnerabilities" and path.name == "records.parquet":
            if len(path.parts) != 5 or path.parts[1] not in COUNTS or ".." in path.parts:
                raise DataError("unexpected capture in committed vulnerability inventory")
            _, source, capture, _, _ = path.parts
            partitions.append((source, capture, path, refs[item["key"]]))
    if len(partitions) != 29 or len({(x[0], x[1]) for x in partitions}) != len(partitions):
        raise DataError("catalog staging requires exactly 29 cve, kev, and nvd captures")

    session, _ = settings.identity()
    outputs = stack_outputs(session, settings)
    workgroup = settings.project
    athena = session.client("athena", config=SDK_CONFIG)
    group = athena.get_work_group(WorkGroup=workgroup)["WorkGroup"]
    conf = group["Configuration"]
    if (
        group["State"] != "ENABLED"
        or not conf["EnforceWorkGroupConfiguration"]
        or not 0 < conf["BytesScannedCutoffPerQuery"] <= SCAN_CUTOFF
        or conf["ResultConfiguration"]["EncryptionConfiguration"]
        != {"EncryptionOption": "SSE_KMS", "KmsKey": outputs["KmsKey"]}
    ):
        raise DataError("catalog staging requires the scan-capped, encrypted Athena workgroup")
    if not put_record(
        store, f"{stage}/attempt-{attempt}.json", {"max_queries": 2, "usd": str(CAP)}, exact=False
    ):
        raise DataError("catalog staging attempt is already reserved")
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
    schema = assign_fresh_schema_ids(Catalog._convert_schema_if_needed(SCHEMA))
    partition = PartitionSpec(
        PartitionField(schema.find_field("source").field_id, 1000, IdentityTransform(), "source")
    )
    database = settings.database
    location = f"s3://{store.bucket}/v2/silver/{database}/{NAME}"
    table = catalog.create_table_if_not_exists(
        (database, NAME),
        schema,
        location=location,
        partition_spec=partition,
        properties={"format-version": "2", "write.parquet.compression-codec": "zstd"},
    )
    if (
        table.format_version != 2
        or table.location() != location
        or table.spec() != partition
        or table.schema().as_struct() != schema.as_struct()
    ):
        raise DataError("existing vulnerability staging table differs from the reviewed layout")
    before = table.current_snapshot()
    captures = {}
    if before:
        for snap in table.snapshots():
            props = snap.summary.additional_properties if snap.summary else {}
            if props.get("aegis.catalog-inventory") != identity:
                raise DataError("catalog stage contains a commit for another inventory")
            captures[props["aegis.capture"]] = props["aegis.capture-sha256"]
    for source, capture, path, ref in partitions:
        label = f"{source}/{capture}"
        if label in captures:
            if captures[label] != ref.sha256:
                raise DataError("an already staged capture differs from the approved inventory")
            continue
        with verified_input(store, ref, cache / path) as file:
            rows = projection(file, source, capture, ref)
        table.append(
            rows,
            snapshot_properties={
                "aegis.catalog-inventory": identity,
                "aegis.capture": label,
                "aegis.capture-sha256": ref.sha256,
            },
        )
        print(json.dumps({"capture": label, "rows": rows.num_rows}), flush=True)
    snapshot = table.current_snapshot().snapshot_id
    with duckdb.connect(config={"threads": "2", "memory_limit": "256MB"}) as db:
        db.register(
            "catalog_slice",
            table.scan(
                snapshot_id=snapshot, selected_fields=("source", "cve_id")
            ).to_arrow_batch_reader(),
        )
        totals = db.sql(
            "SELECT source, count(*), count(DISTINCT cve_id) FROM catalog_slice GROUP BY 1"
        ).fetchall()
        # The Arrow reader is consumed by the first aggregation.
        db.register(
            "catalog_ids",
            table.scan(snapshot_id=snapshot, selected_fields=("cve_id",)).to_arrow_batch_reader(),
        )
        distinct = db.sql("SELECT count(DISTINCT cve_id) FROM catalog_ids").fetchone()[0]
    observed = {k: (total, unique) for k, total, unique in totals}
    if observed != COUNTS:
        raise DataError("Iceberg source coverage differs from the verified local corpus")

    rel = f'"{database}"."{NAME}" FOR VERSION AS OF {snapshot}'
    reader = AthenaReader(athena, database, workgroup)
    grouped, first = reader._select(
        "SELECT source, count(*) records, count(DISTINCT cve_id) unique_cves "
        f"FROM {rel} GROUP BY 1",
        max_rows=3,
    )
    query = f"SELECT count(DISTINCT cve_id) unique_cves FROM {rel}"
    union, second = reader._select(query, max_rows=1)
    if {
        row["source"]: (row["records"], row["unique_cves"]) for row in grouped
    } != observed or union[0]["unique_cves"] != distinct:
        raise DataError("DuckDB and Athena catalog counts differ")
    row = {
        "state": "passed",
        "inventory": identity,
        "table": NAME,
        "database": database,
        "table_version": 2,
        "snapshot": snapshot,
        "distinct_cves": distinct,
        "sources": observed,
        "athena": [first, second],
        "evidence": {f"{source}/{capture}": asdict(ref) for source, capture, _, ref in partitions},
    }
    manifest = {"component": plan_id(row), **row}
    put_record(store, f"{stage}/committed.json", manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--cache", default=Path("data/v2"), type=Path)
    parser.add_argument("--attempt", default=1, type=int, choices=(1, 2, 3))
    args = parser.parse_args()
    result = publish(args.inventory, args.attempt, args.cache)
    write_json(args.evidence / "v2-catalog-silver.json", result)
    print(
        json.dumps({key: result[key] for key in ("state", "snapshot", "distinct_cves", "athena")})
    )


if __name__ == "__main__":
    try:
        main()
    except ClientError as error:
        raise SystemExit(f"Catalog staging AWS error: {error.response['Error']['Code']}") from None
    except (DataError, OSError, ValueError, KeyError) as error:
        raise SystemExit(f"Catalog staging failed: {error}") from None
