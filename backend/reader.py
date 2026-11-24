"""Bounded snapshot reads shared by REST and MCP."""

from collections.abc import Callable
from datetime import date
from enum import StrEnum
from functools import cached_property
from pathlib import Path
from threading import BoundedSemaphore, Timer
from typing import Any
from uuid import UUID

import duckdb
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import BaseModel

from backend.geography import (
    MapEnvelope,
    NetworkContext,
    NetworkLayer,
    load_context,
    unavailable_exposure,
)
from backend.investigations.timing import measure
from backend.models import (
    Coverage,
    Edge,
    Envelope,
    Evidence,
    Exposure,
    Filters,
    RiskSummary,
    ServiceError,
    Vulnerability,
)
from pipelines.athena import AthenaReader, relation
from pipelines.cloud import Published
from pipelines.io import DataError, selected_snapshot
from pipelines.publish import load_run, validate_published
from pipelines.query import Query, connect, query_template

Row = dict[str, Any]
Param = str | date | float | int
Read = Callable[[str, list[Param], int], list[Row]]
SourceRelation = Callable[[str], str]
TIME_LIMIT = 5
RECENCY = """
ROW_NUMBER() OVER (
    PARTITION BY cve_id, country_iso2, source, scope, unit
    ORDER BY snapshot_at DESC, evidence_id
)
"""


class View(StrEnum):
    CVES = "cves"
    MAP = "map"
    GRAPH = "graph"
    KPIS = "kpis"


def sql_literal(value: Param) -> str:
    if isinstance(value, date):
        return f"DATE '{value.isoformat()}'"
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    return str(value)


def statement(
    view: View, filters: Filters, table: SourceRelation, *, athena: bool = False
) -> tuple[str, list[Param], int]:
    terms: list[str] = []
    params: list[Param] = []
    if filters.cve_ids:
        marks = ", ".join("?" for _ in filters.cve_ids)
        terms.append(f"c.cve_id IN ({marks})")
        params.extend(filters.cve_ids)
    if filters.kev_only:
        terms.append("c.kev")
    for clause, value in (
        ("e.epss >= ?", filters.min_epss),
        ("c.severity = ?", filters.severity),
        ("c.kev_added_at >= ?", filters.date_from),
        ("c.kev_added_at <= ?", filters.date_to),
    ):
        if value is not None:
            terms.append(clause)
            params.append(value)
    geo = table("fact_geo_exposure")
    if filters.country_iso2:
        terms.append(f"EXISTS (SELECT 1 FROM {geo} g WHERE g.cve_id=c.cve_id AND g.country_iso2=?)")
        params.append(filters.country_iso2)
    predicate = " AND ".join(terms) if terms else "TRUE"
    scope = f"""
    WITH candidates AS (
        SELECT c.*, e.epss, e.percentile, e.score_date, e.source_ref AS epss_evidence_id
        FROM {table("dim_cve")} c
        LEFT JOIN {table("fact_epss_latest")} e ON c.cve_id=e.cve_id
        WHERE {predicate}
    )
    """
    if view == View.KPIS:
        return (
            scope
            + """
        SELECT COUNT(*) AS total_cves, COUNT(*) FILTER (WHERE kev) AS kev_cves,
               COUNT(published_at) AS with_nvd, COUNT(epss) AS with_epss,
               COUNT(*) FILTER (WHERE epss >= 0.5) AS high_epss
        FROM candidates
        """,
            params,
            1,
        )
    if view == View.CVES:
        refs = "JSON_FORMAT(CAST(source_refs AS JSON)) AS source_refs" if athena else "source_refs"
        body = f"""
        SELECT cve_id, description, kev, kev_added_at, severity, cvss_score, cvss_version,
               cvss_source, epss, percentile, score_date, {refs}, epss_evidence_id
        FROM candidates
        ORDER BY kev DESC, epss DESC NULLS LAST, cvss_score DESC NULLS LAST, cve_id
        """
    elif view == View.GRAPH:
        body = f"""
        , edges AS (
            SELECT b.cve_id, b.relation_type, p.product_id AS target_id, p.product AS target_label,
                   p.vendor, b.evidence_id
            FROM {table("bridge_cve_product")} b
            JOIN {table("dim_product")} p ON b.product_id=p.product_id
            JOIN candidates c ON b.cve_id=c.cve_id
            UNION ALL
            SELECT b.cve_id, 'classified_as', b.cwe_id, b.cwe_id, CAST(NULL AS VARCHAR),
                   b.evidence_id
            FROM {table("bridge_cve_cwe")} b JOIN candidates c ON b.cve_id=c.cve_id
        )
        SELECT * FROM edges ORDER BY cve_id, relation_type, target_id, evidence_id
        """
    else:
        selected_country = " AND g.country_iso2=?" if filters.country_iso2 else ""
        if filters.country_iso2:
            params.append(filters.country_iso2)
        body = f"""
        , observations AS (
            SELECT g.*, {RECENCY} AS recency
            FROM {geo} g WHERE g.country_iso2 IS NOT NULL{selected_country}
              AND g.cve_id IN (SELECT cve_id FROM candidates)
        )
        SELECT cve_id, country_iso2, snapshot_at, source, scope, "count", unit, confidence,
               coverage, evidence_id
        FROM observations WHERE recency=1
        ORDER BY country_iso2, cve_id, source, scope, unit
        """
    return scope + body + f" LIMIT {filters.limit}", params, filters.limit


class SnapshotReader:
    def __init__(
        self,
        snapshot: UUID,
        score_date: date,
        read: Read,
        table: SourceRelation,
        *,
        geo_available: bool,
        athena: bool = False,
        cisa_archive: Callable[[], bytes] | None = None,
        network: tuple[NetworkContext, ...] = (),
    ) -> None:
        self.snapshot = snapshot
        self.score_date = score_date
        self.read = read
        self.table = table
        self.geo_available = geo_available
        self.athena = athena
        self.cisa_archive = cisa_archive
        self.network = network
        self.slots = BoundedSemaphore(2)

    @classmethod
    def duckdb(cls, root: Path, snapshot: UUID | None) -> "SnapshotReader":
        folder = selected_snapshot(root, snapshot)
        manifest = validate_published(root, folder)
        if manifest["status"] != "ok":
            raise DataError("backend requires a validated snapshot")
        run = load_run(folder)

        def read(sql: str, params: list[Param], max_rows: int) -> list[Row]:
            with connect(folder / "aegis.duckdb") as conn:
                timer = Timer(TIME_LIMIT, conn.interrupt)
                timer.start()
                try:
                    cursor = conn.execute(sql, params)
                    names = [col[0] for col in cursor.description]
                    rows = cursor.fetchmany(max_rows + 1)
                    if len(rows) > max_rows:
                        raise ServiceError("row_budget", "query exceeded its row budget", 503)
                    return [dict(zip(names, row, strict=True)) for row in rows]
                finally:
                    timer.cancel()
                    timer.join()

        def cisa_archive() -> bytes:
            with (folder / "raw" / "00-cisa.json").open("rb") as raw:
                blob = raw.read(4 * 1024 * 1024 + 1)
            if len(blob) > 4 * 1024 * 1024:
                raise DataError("CISA archive exceeds its byte budget")
            return blob

        return cls(
            run.run_id,
            max(run.epss_history),
            read,
            lambda name: name,
            geo_available=manifest["geometry"]["status"] == "available",
            cisa_archive=cisa_archive,
            network=load_context(root / "network" / str(run.run_id), run.run_id),
        )

    @classmethod
    def cloud(
        cls,
        reader: AthenaReader,
        release: Published,
        *,
        geo_available: bool,
        cisa_archive: Callable[[], bytes] | None = None,
        network: tuple[NetworkContext, ...] = (),
    ) -> "SnapshotReader":
        def table(name: str) -> str:
            if name == "fact_epss_latest":
                facts = relation(reader.database, "fact_epss", release)
                return f"(SELECT * FROM {facts} WHERE score_date={sql_literal(release.score_date)})"
            return relation(reader.database, name, release)

        def read(sql: str, params: list[Param], max_rows: int) -> list[Row]:
            chunks = sql.split("?")
            rendered = (
                "".join(
                    segment + sql_literal(value)
                    for segment, value in zip(chunks[:-1], params, strict=True)
                )
                + chunks[-1]
            )
            return reader._select(rendered, max_rows=max_rows)[0]

        return cls(
            release.run_id,
            release.score_date,
            read,
            table,
            geo_available=geo_available,
            athena=True,
            cisa_archive=cisa_archive,
            network=network,
        )

    def rows(self, sql: str, params: list[Param], max_rows: int) -> list[Row]:
        if not self.slots.acquire(blocking=False):
            raise ServiceError("busy", "query capacity is temporarily exhausted", 503)
        try:
            with measure("athena.read" if self.athena else "duckdb.read"):
                return self.read(sql, params, max_rows)
        except duckdb.InterruptException as error:
            raise ServiceError("timeout", "query budget exceeded", 504) from error
        except (BotoCoreError, ClientError, DataError, duckdb.Error) as error:
            raise ServiceError("data_unavailable", "snapshot query failed", 503) from error
        finally:
            self.slots.release()

    def coverage(self) -> list[Coverage]:
        return [value.model_copy() for value in self.coverage_rows]

    @cached_property
    def coverage_rows(self) -> tuple[Coverage, ...]:
        sql, _ = query_template(Query.COVERAGE)
        sql = sql.replace("FROM ingestion_runs", f"FROM {self.table('ingestion_runs')}")
        return tuple(Coverage.model_validate(row) for row in self.rows(sql, [], 4))

    def envelope[T](self, data: T, *, regional: bool = False) -> Envelope[T]:
        return Envelope(
            snapshot_id=self.snapshot,
            score_date=self.score_date,
            coverage=self.coverage(),
            availability="unavailable" if regional and not self.geo_available else "available",
            data=data,
        )

    def view_rows[T: BaseModel](self, view: View, filters: Filters, model: type[T]) -> list[T]:
        sql, params, cap = statement(view, filters, self.table, athena=self.athena)
        return [model.model_validate(row) for row in self.rows(sql, params, cap)]

    def vulnerabilities(self, filters: Filters) -> Envelope[list[Vulnerability]]:
        return self.envelope(
            self.view_rows(View.CVES, filters, Vulnerability),
            regional=filters.country_iso2 is not None,
        )

    def risk(self, filters: Filters) -> Envelope[RiskSummary]:
        (summary,) = self.view_rows(View.KPIS, filters, RiskSummary)
        return self.envelope(summary, regional=filters.country_iso2 is not None)

    def map(self, filters: Filters) -> Envelope[list[Exposure]]:
        return Envelope(
            snapshot_id=self.snapshot,
            score_date=self.score_date,
            coverage=self.coverage(),
            availability="unavailable",
            data=[],
        )

    @cached_property
    def archived_kev(self) -> bytes | None:
        return self.cisa_archive() if self.cisa_archive else None

    def geography(self, filters: Filters) -> MapEnvelope:
        # No current source is qualified for exposure. Prior lake data alone cannot grant
        # publication permission or establish a measured zero.
        records = [
            row
            for row in self.network
            if filters.country_iso2 is None or filters.country_iso2 == row.country_iso2
        ]
        network = NetworkLayer(
            state="available" if records else "unavailable",
            records=records,
            note=(
                "Published network context for the selected area."
                if records
                else "No qualified network context covers the selected area."
            ),
        )
        return MapEnvelope(
            snapshot_id=self.snapshot,
            score_date=self.score_date,
            coverage=self.coverage(),
            availability="unavailable",
            data=[],
            exposure=unavailable_exposure(filters.country_iso2),
            network=network,
        )

    def graph(self, filters: Filters) -> Envelope[list[Edge]]:
        return self.envelope(
            self.view_rows(View.GRAPH, filters, Edge), regional=filters.country_iso2 is not None
        )

    def evidence(self, identifier: str) -> Envelope[Evidence]:
        source = self.table("evidence")
        rows = self.rows(
            "SELECT evidence_id, source, source_record_id, retrieved_at, source_date, checksum, "
            f"uri, license FROM {source} WHERE evidence_id=? LIMIT 1",
            [identifier],
            1,
        )
        if not rows:
            raise ServiceError("not_found", "evidence was not found in this snapshot", 404)
        return self.envelope(Evidence.model_validate(rows[0]))
