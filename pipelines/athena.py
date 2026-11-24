"""Athena engine 3 adapter for the allowlisted G1 query templates."""

import json
import re
import time
from datetime import UTC, date, datetime
from typing import Any

from botocore.client import BaseClient

from pipelines.cloud import Published
from pipelines.io import DataError
from pipelines.query import Query, query_template
from schemas.tables import GRAINS, TABLES

QUERY_TIMEOUT_SECONDS = 45


def relation(database: str, name: str, release: Published) -> str:
    if name not in TABLES or not re.fullmatch(r"aegis_[a-z0-9_]+", database):
        raise DataError("athena: unexpected database or table")
    release.check()
    return f'"{database}"."{name}" FOR VERSION AS OF {release.snapshots[name]}'


def render(
    database: str,
    release: Published,
    name: Query,
    *,
    limit: int = 100,
    min_epss: float | None = None,
    country_iso2: str | None = None,
) -> str:
    body, params = query_template(name, limit=limit, min_epss=min_epss, country_iso2=country_iso2)
    # Athena parameters can appear only in WHERE. Inline these validated
    # limits, finite numeric thresholds, and two-letter ISO country codes.
    chunks = body.split("?")
    if len(chunks) != len(params) + 1:
        raise DataError("athena: template parameter count changed")
    body = (
        "".join(
            chunk + ("NULL" if param is None else repr(param))
            for chunk, param in zip(chunks[:-1], params, strict=True)
        )
        + chunks[-1]
    )
    used_tables = {
        Query.RANKING: ("dim_cve",),
        Query.COVERAGE: ("ingestion_runs",),
        Query.GRAPH: ("bridge_cve_product", "dim_product", "bridge_cve_cwe"),
        Query.GEO: ("fact_geo_exposure",),
    }[name]
    ctes = [
        f"{table} AS (SELECT * FROM {relation(database, table, release)})" for table in used_tables
    ]
    if name == Query.RANKING:
        ctes.append(
            "fact_epss_latest AS ("
            f"SELECT * FROM {relation(database, 'fact_epss', release)} "
            f"WHERE score_date = DATE '{release.score_date.isoformat()}')"
        )
        body = body.replace(
            "c.source_refs,", "JSON_FORMAT(CAST(c.source_refs AS JSON)) AS source_refs,"
        )
    prefix = "WITH " + ",\n".join(ctes)
    return prefix + (",\n" + body[5:] if body.startswith("WITH ") else "\n" + body)


def value_for(name: str, sql_type: str, value: str | None) -> Any:
    if value is None:
        return None
    if name == "source_refs":
        result = json.loads(value)
        if not isinstance(result, list) or not all(isinstance(item, str) for item in result):
            raise DataError("athena: invalid source_refs")
        return result
    if sql_type in ("bigint", "integer", "smallint", "tinyint"):
        return int(value)
    if sql_type in ("double", "real"):
        return float(value)
    if sql_type == "boolean":
        return value == "true"
    if sql_type == "date":
        return date.fromisoformat(value)
    if sql_type.startswith("timestamp"):
        parsed = datetime.fromisoformat(value.removesuffix(" UTC"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    return value


class AthenaReader:
    def __init__(self, client: BaseClient, database: str, workgroup: str) -> None:
        self.client = client
        self.database = database
        self.workgroup = workgroup

    def _select(self, sql: str, *, max_rows: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        execution_id = self.client.start_query_execution(
            QueryString=sql,
            QueryExecutionContext={"Database": self.database},
            WorkGroup=self.workgroup,
        )["QueryExecutionId"]
        deadline = time.monotonic() + QUERY_TIMEOUT_SECONDS
        state = "QUEUED"
        try:
            while time.monotonic() < deadline:
                execution = self.client.get_query_execution(QueryExecutionId=execution_id)[
                    "QueryExecution"
                ]
                state = execution["Status"]["State"]
                if state == "SUCCEEDED":
                    break
                if state in ("FAILED", "CANCELLED"):
                    reason = execution["Status"].get("AthenaError", {}).get("ErrorType", "unknown")
                    message = execution["Status"].get("StateChangeReason", "")
                    raise DataError(f"athena: query {state.lower()} ({reason}): {message[:250]}")
                time.sleep(0.4)
            else:
                raise DataError("athena: query exceeded its polling budget")
        except BaseException:
            if state not in ("SUCCEEDED", "FAILED", "CANCELLED"):
                self.client.stop_query_execution(QueryExecutionId=execution_id)
            raise
        return self.completed_result(execution, max_rows=max_rows)

    def completed_result(
        self, execution: dict[str, Any], *, max_rows: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if execution["Status"]["State"] != "SUCCEEDED":
            raise DataError("athena: query results require a successful execution")
        execution_id = execution["QueryExecutionId"]
        rows: list[dict[str, Any]] = []
        results = self.client.get_paginator("get_query_results").paginate(
            QueryExecutionId=execution_id, PaginationConfig={"PageSize": 500}
        )
        first_page = True
        for page in results:
            result = page["ResultSet"]
            columns = result["ResultSetMetadata"]["ColumnInfo"]
            for row in result["Rows"][int(first_page) :]:
                values = row["Data"]
                rows.append(
                    {
                        col["Name"]: value_for(
                            col["Name"],
                            col["Type"],
                            values[index].get("VarCharValue") if index < len(values) else None,
                        )
                        for index, col in enumerate(columns)
                    }
                )
                if len(rows) > max_rows:
                    raise DataError("athena: query exceeded its row budget")
            first_page = False
        stats = execution["Statistics"]
        return rows, {
            "query_id": execution_id,
            "scanned_bytes": stats["DataScannedInBytes"],
            "total_ms": stats["TotalExecutionTimeInMillis"],
        }

    def query(
        self,
        release: Published,
        name: Query,
        *,
        limit: int = 100,
        min_epss: float | None = None,
        country_iso2: str | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        statement = render(
            self.database, release, name, limit=limit, min_epss=min_epss, country_iso2=country_iso2
        )
        return self._select(statement, max_rows=4 if name == Query.COVERAGE else limit)

    def verify_counts(self, release: Published, expected: dict[str, int]) -> list[dict[str, Any]]:
        stats = []
        for name, keys in GRAINS.items():
            # Identifiers are from the fixed canonical schemas. Counting grain
            # groups also checks duplicate keys when nulls occur in a key.
            columns = ", ".join(f'"{column}"' for column in keys)
            source = relation(self.database, name, release)
            rows, query_stats = self._select(
                "SELECT COALESCE(SUM(grain_rows), 0) AS row_total, COUNT(*) AS grain_total "
                f"FROM (SELECT COUNT(*) AS grain_rows FROM {source} GROUP BY {columns})",
                max_rows=1,
            )
            if rows != [{"row_total": expected[name], "grain_total": expected[name]}]:
                raise DataError(f"athena: count or grain mismatch for {name}")
            stats.append({"table": name, "rows": expected[name], **query_stats})
        return stats
