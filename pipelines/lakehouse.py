"""Iceberg writer shared by the cloud ingester and the real-snapshot integration tests."""

import json
from datetime import date
from pathlib import Path

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq
from pyiceberg.catalog import Catalog
from pyiceberg.expressions import In
from pyiceberg.partitioning import PartitionField, PartitionSpec
from pyiceberg.schema import assign_fresh_schema_ids
from pyiceberg.table import Table
from pyiceberg.transforms import IdentityTransform

from pipelines.io import DataError, file_digest, snapshot_directory
from pipelines.publish import load_run
from schemas.tables import TABLES

EPSS = "fact_epss"
RELEASE = "aegis.release"
PARTITIONS = "aegis.epss-partitions"


def init_tables(catalog: Catalog, database: str, warehouse: str) -> dict[str, Table]:
    tables = {}
    for name, arrow in TABLES.items():
        # The catalog assigns field IDs when creating a table. Use the same
        # ordering when verifying existing tables and finding the partition ID.
        schema = assign_fresh_schema_ids(Catalog._convert_schema_if_needed(arrow))
        spec = PartitionSpec()
        if name == EPSS:
            spec = PartitionSpec(
                PartitionField(
                    source_id=schema.find_field("score_date").field_id,
                    field_id=1000,
                    transform=IdentityTransform(),
                    name="score_date",
                )
            )
        location = f"{warehouse}/{name}"
        table = catalog.create_table_if_not_exists(
            (database, name),
            schema,
            location=location,
            partition_spec=spec,
            properties={"format-version": "2", "write.parquet.compression-codec": "zstd"},
        )
        if (
            table.format_version != 2
            or table.schema().as_struct() != schema.as_struct()
            or table.spec() != spec
            or table.location() != location
        ):
            raise DataError(f"{name}: existing Iceberg table differs from the canonical contract")
        tables[name] = table
    return tables


def athena_timestamps(rows: pa.Table) -> pa.Table:
    # Preserve the original microseconds in raw/Parquet. Athena engine 3 reads
    # Iceberg timestamps at millisecond precision, so floor only the cloud copy.
    for index, field in enumerate(rows.schema):
        if pa.types.is_timestamp(field.type):
            values = pc.floor_temporal(rows.column(index), unit="millisecond")
            rows = rows.set_column(index, field, values)
    return rows


def commit_tables(
    tables: dict[str, Table], root: Path, folder: Path
) -> tuple[dict[str, int], date]:
    run = load_run(folder)
    latest = max(run.epss_history)
    epss_sources = {
        day: (folder if day == latest else snapshot_directory(root, run_id))
        / "parquet"
        / f"{EPSS}.parquet"
        for day, run_id in sorted(run.epss_history.items())
    }
    epss_checksums = {day.isoformat(): file_digest(path) for day, path in epss_sources.items()}
    snapshots: dict[str, int] = {}
    for name, table in tables.items():
        current = table.current_snapshot()
        summary = current.summary.additional_properties if current and current.summary else {}
        if name == EPSS:
            committed = json.loads(summary.get(PARTITIONS, "{}"))
            changed = {
                date.fromisoformat(day)
                for day in committed.keys() | epss_checksums.keys()
                if committed.get(day) != epss_checksums.get(day)
            }
            if changed or current is None:
                changed_rows = [
                    pq.read_table(path) for day, path in epss_sources.items() if day in changed
                ]
                rows = (
                    pa.concat_tables(changed_rows) if changed_rows else TABLES[EPSS].empty_table()
                )
                props = {
                    RELEASE: folder.name,
                    PARTITIONS: json.dumps(epss_checksums, sort_keys=True),
                }
                # Drop whole obsolete partitions, then append only changed/new days.
                with table.transaction() as tx:
                    if replaced := [day for day in changed if day.isoformat() in committed]:
                        tx.delete(In("score_date", replaced))
                    tx.append(rows, snapshot_properties=props)
        elif summary.get(RELEASE) != folder.name:
            rows = athena_timestamps(pq.read_table(folder / "parquet" / f"{name}.parquet"))
            props = {RELEASE: folder.name}
            if current is None:
                table.append(rows, snapshot_properties=props)
            else:
                table.overwrite(rows, snapshot_properties=props)
        current = table.current_snapshot()
        if current is None:
            raise DataError(f"{name}: no Iceberg snapshot after commit")
        snapshots[name] = current.snapshot_id
    return snapshots, latest
