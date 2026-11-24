"""Real provider artifacts round-tripped through the PyIceberg writer."""

import json
import os
from datetime import date
from pathlib import Path
from uuid import UUID

import pytest
from pyiceberg.catalog.sql import SqlCatalog

from infra.operations import normalize_times
from pipelines.athena import relation, render
from pipelines.cloud import Published
from pipelines.io import selected_snapshot
from pipelines.lakehouse import commit_tables, init_tables
from pipelines.publish import validate_published
from pipelines.query import Query, connect, query
from schemas.tables import GRAINS

pytestmark = pytest.mark.live


def test_iceberg_v2_real_snapshot(tmp_path: Path) -> None:
    root = Path(os.environ["AEGIS_DATA_DIR"])
    folder = selected_snapshot(root, UUID(os.environ["AEGIS_SNAPSHOT"]))
    manifest = validate_published(root, folder)

    database = "aegis_integration"
    warehouse = (tmp_path / "warehouse").as_uri()
    catalog = SqlCatalog("local", uri=f"sqlite:///{tmp_path / 'catalog.db'}", warehouse=warehouse)
    catalog.create_namespace(database)
    tables = init_tables(catalog, database, warehouse)
    snapshots, day = commit_tables(tables, root, folder)
    # Reload from catalog between writes to catch persistence bugs.
    tables = init_tables(catalog, database, warehouse)
    assert commit_tables(tables, root, folder) == (snapshots, day)
    release = Published(run_id=folder.name, score_date=day, snapshots=snapshots).check()

    comparison = tmp_path / "comparison.duckdb"
    with connect(comparison, read_only=False) as db, connect(folder / "aegis.duckdb") as expected:
        for name, table in tables.items():
            arrow = table.scan(snapshot_id=snapshots[name]).to_arrow()
            assert arrow.num_rows == manifest["row_counts"][name]
            assert len(table.snapshots()) == 1
            db.register("incoming", arrow)
            db.execute(f"CREATE TABLE {name} AS SELECT * FROM incoming")
            db.unregister("incoming")
            keys = ", ".join(GRAINS[name])
            assert (
                db.execute(
                    f"SELECT 1 FROM {name} GROUP BY {keys} HAVING COUNT(*) > 1 LIMIT 1"
                ).fetchone()
                is None
            )
        db.execute("CREATE SCHEMA aegis_integration")
        for name in tables:
            db.execute(f"CREATE VIEW aegis_integration.{name} AS SELECT * FROM main.{name}")
        db.execute("CREATE MACRO json_format(x) AS CAST(x AS VARCHAR)")
        for template, options in (
            (Query.COVERAGE, {}),
            (Query.RANKING, {"limit": 1000}),
            (Query.RANKING, {"limit": 1000, "min_epss": 0.5}),
            (Query.GRAPH, {"limit": 1000}),
            (Query.GEO, {}),
            (Query.GEO, {"country_iso2": "PE"}),
        ):
            statement = render(database, release, template, **options)
            # DuckDB lacks Athena's version-travel syntax. The loaded Arrow
            # tables were already pinned by snapshot ID above.
            for name in tables:
                source = relation(database, name, release)
                statement = statement.replace(source, source.rsplit(" FOR VERSION AS OF ", 1)[0])
            cursor = db.execute(statement)
            values = [
                dict(zip((item[0] for item in cursor.description), row, strict=True))
                for row in cursor.fetchall()
            ]
            for row in values:
                if "source_refs" in row:
                    row["source_refs"] = json.loads(row["source_refs"])
            assert values == normalize_times(query(expected, template, **options))
        assert db.execute("SELECT MAX(score_date) FROM fact_epss").fetchone() == (day,)
        assert type(day) is date
