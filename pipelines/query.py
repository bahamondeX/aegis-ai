import os
import re
from enum import StrEnum
from pathlib import Path
from typing import Any

import duckdb

from pipelines.io import DataError
from schemas.tables import TABLES

SQL = Path(__file__).resolve().parents[1] / "sql"


class Query(StrEnum):
    RANKING = "ranked_kev"
    COVERAGE = "coverage"
    GRAPH = "relationship_graph"
    GEO = "exposure_by_country"


def connect(path: Path, *, read_only: bool = True) -> duckdb.DuckDBPyConnection:
    config = {"threads": "2", "memory_limit": "768MB"}
    if extensions := os.getenv("AEGIS_DUCKDB_EXTENSION_DIR"):
        config.update(extension_directory=extensions, autoinstall_known_extensions="false")
    config["TimeZone"] = "UTC"
    return duckdb.connect(
        str(path),
        read_only=read_only,
        config=config,
    )


def create_views(folder: Path, history: list[Path]) -> None:
    with connect(folder / "aegis.duckdb", read_only=False) as db:
        for table in TABLES:
            current = folder / "parquet" / f"{table}.parquet"
            files = [current, *history] if table == "fact_epss" else [current]
            # read_parquet binds filenames during CREATE VIEW. All paths are local artifacts.
            relation = db.read_parquet([str(path) for path in files])
            relation.create_view(table, replace=True)
        db.sql("CREATE VIEW fact_epss_history AS SELECT * FROM fact_epss")
        db.sql("""
            CREATE VIEW fact_epss_latest AS
            SELECT * FROM fact_epss WHERE score_date = (SELECT MAX(score_date) FROM fact_epss)
        """)


def query(
    db: duckdb.DuckDBPyConnection,
    name: Query,
    *,
    limit: int = 100,
    min_epss: float | None = None,
    country_iso2: str | None = None,
) -> list[dict[str, Any]]:
    statement, params = query_template(
        name, limit=limit, min_epss=min_epss, country_iso2=country_iso2
    )
    cursor = db.execute(statement, params)
    return [
        dict(zip((col[0] for col in cursor.description), row, strict=True))
        for row in cursor.fetchall()
    ]


def query_template(
    name: Query,
    *,
    limit: int = 100,
    min_epss: float | None = None,
    country_iso2: str | None = None,
) -> tuple[str, list[float | int | str | None]]:
    if not isinstance(name, Query):
        raise DataError("query: unknown template")
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise DataError("query: limit must be in [1, 1000]")
    if min_epss is not None and (
        name != Query.RANKING or type(min_epss) not in (float, int) or not 0 <= min_epss <= 1
    ):
        raise DataError("query: invalid EPSS threshold")
    if country_iso2 is not None and (
        name != Query.GEO
        or not isinstance(country_iso2, str)
        or not re.fullmatch(r"[A-Z]{2}", country_iso2)
    ):
        raise DataError("query: invalid country filter")
    params_by_query: dict[Query, list[float | int | str | None]] = {
        Query.RANKING: [min_epss, min_epss, limit],
        Query.COVERAGE: [],
        Query.GRAPH: [limit],
        Query.GEO: [country_iso2, country_iso2, limit],
    }
    return (SQL / f"{name.value}.sql").read_text(), params_by_query[name]
