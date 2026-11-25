"""FastAPI and official MCP Streamable HTTP over one snapshot reader."""

import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Annotated
from uuid import UUID

import anyio
from fastapi import APIRouter, Depends, FastAPI, Query, Request, Security
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from starlette.datastructures import Headers
from starlette.types import Receive, Scope, Send

from backend.auth import Auth
from backend.cve_detail import detail, guidance
from backend.geography import MapEnvelope
from backend.models import (
    Country,
    Coverage,
    CveDetail,
    Edge,
    Envelope,
    Evidence,
    EvidenceId,
    Exposure,
    FilterCve,
    Filters,
    MitigationVulnerability,
    RiskSummary,
    ServiceError,
    Vulnerability,
)
from backend.reader import SnapshotReader
from backend.v2_catalog import CatalogFilters, CatalogPage, CatalogReader
from backend.v2_network import NetworkContextReader, NetworkYear, WdiAlpha2
from backend.v2_series import DailyRiskSeries, RiskSeriesReader, SeriesFilters

if TYPE_CHECKING:
    from backend.investigations.service import InvestigationService

FilterQuery = Annotated[Filters, Query()]
Token = Annotated[HTTPAuthorizationCredentials | None, Security(HTTPBearer(auto_error=False))]


def error_response(error: ServiceError) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if error.status == 401 else None
    return JSONResponse(
        {"error": {"code": error.code, "message": str(error)}},
        status_code=error.status,
        headers=headers,
    )


async def mcp_result[T](call: Callable[[], T]) -> T:
    try:
        return await anyio.to_thread.run_sync(call)
    except ServiceError as error:
        raise ToolError(json.dumps({"code": error.code, "message": str(error)})) from None


def create_app(
    reader: SnapshotReader | Callable[[], SnapshotReader],
    auth: Auth,
    investigations: "InvestigationService | None" = None,
    *,
    runtime: bool = False,
    network: NetworkContextReader | Callable[[], NetworkContextReader] | None = None,
    catalog: CatalogReader | Callable[[], CatalogReader] | None = None,
    series: RiskSeriesReader | Callable[[], RiskSeriesReader] | None = None,
) -> FastAPI:
    def snapshot_reader() -> SnapshotReader:
        return reader() if callable(reader) else reader

    mcp = FastMCP("AEGIS", stateless_http=True, json_response=True, streamable_http_path="/")

    def network_reader() -> NetworkContextReader:
        if network is None:
            raise ServiceError("release_unavailable", "Network context is unavailable", 503)
        return network() if callable(network) else network

    def catalog_page(filters: CatalogFilters | None) -> CatalogPage:
        if catalog is None:
            raise ServiceError("release_unavailable", "The catalog release is unavailable", 503)
        current = catalog() if callable(catalog) else catalog
        selection = filters or CatalogFilters()
        return current.page(
            selection.year, limit=selection.limit, after=selection.after, cve_id=selection.cve_id
        )

    if catalog is not None:

        @mcp.tool()
        async def get_catalog(filters: CatalogFilters | None = None) -> CatalogPage:
            """Read a bounded page from the verified official vulnerability catalog."""
            return await mcp_result(lambda: catalog_page(filters))

    def risk_series(filters: SeriesFilters | None) -> DailyRiskSeries:
        if series is None:
            raise ServiceError("release_unavailable", "EPSS history is unavailable", 503)
        current = series() if callable(series) else series
        return current.series(filters or SeriesFilters())

    if series is not None:

        @mcp.tool()
        async def get_global_epss_series(filters: SeriesFilters | None = None) -> DailyRiskSeries:
            """Read a pinned, global daily EPSS series with gaps and model versions preserved."""
            return await mcp_result(lambda: risk_series(filters))

    if network is not None:

        @mcp.tool()
        async def get_global_network_context(
            year: Annotated[int | None, Query(ge=1960, le=2100)] = None,
            country_alpha2: WdiAlpha2 | None = None,
        ) -> NetworkYear:
            """Read annual WDI/ITU subscription statistics at the published economy grain."""
            return await mcp_result(lambda: network_reader().year(year, country_alpha2))

    @mcp.tool()
    async def get_vulnerabilities(
        filters: Filters | None = None, include_mitigation: bool = False
    ) -> Envelope[list[MitigationVulnerability]]:
        """Read ranked vulnerabilities. Archived guidance requires a single explicit CVE."""

        def read() -> Envelope[list[MitigationVulnerability]]:
            selection = filters or Filters()
            if include_mitigation and (
                len(selection.cve_ids) != 1 or selection.country_iso2 or selection.limit != 1
            ):
                raise ServiceError(
                    "invalid_scope", "mitigation requires a single explicit CVE", 422
                )
            ranked = snapshot_reader().vulnerabilities(selection)
            records = []
            for row in ranked.data:
                text = (
                    guidance(snapshot_reader(), row.cve_id, row.source_refs[0])
                    if include_mitigation and row.kev and row.source_refs
                    else None
                )
                records.append(MitigationVulnerability(**row.model_dump(), mitigation=text))
            return snapshot_reader().envelope(records, regional=selection.country_iso2 is not None)

        return await mcp_result(read)

    @mcp.tool()
    async def get_risk_summary(filters: Filters | None = None) -> Envelope[RiskSummary]:
        """Count the filtered cohort and its EPSS and NVD coverage."""
        return await mcp_result(lambda: snapshot_reader().risk(filters or Filters()))

    @mcp.tool()
    async def get_exposure_by_country(filters: Filters | None = None) -> Envelope[list[Exposure]]:
        """Read verified geographic observations or report unavailable coverage."""
        return await mcp_result(lambda: snapshot_reader().map(filters or Filters()))

    @mcp.tool()
    async def get_relationship_graph(filters: Filters | None = None) -> Envelope[list[Edge]]:
        """Read evidence-backed CVE to product and CWE relationships."""
        return await mcp_result(lambda: snapshot_reader().graph(filters or Filters()))

    @mcp.tool()
    async def get_evidence(evidence_id: EvidenceId) -> Envelope[Evidence]:
        """Resolve a published evidence identifier to source provenance."""
        return await mcp_result(lambda: snapshot_reader().evidence(evidence_id))

    @mcp.tool()
    async def propose_ui_filters(filters: Filters) -> Envelope[Filters]:
        """Return a typed proposal for the caller to review."""
        return await mcp_result(lambda: snapshot_reader().envelope(filters))

    mcp_app = mcp.streamable_http_app()

    async def guarded_mcp(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        client = scope.get("client")
        client_ip = client[0] if client else None
        try:
            await anyio.to_thread.run_sync(
                auth.authenticate, Headers(scope=scope).get("authorization"), client_ip
            )
        except ServiceError as error:
            await error_response(error)(scope, receive, send)
            return
        await mcp_app(scope, receive, send)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        async with mcp.session_manager.run():
            yield

    app = FastAPI(title="AEGIS Threat Intelligence", version="1.0.0", lifespan=lifespan)

    @app.exception_handler(ServiceError)
    async def service_error(_: Request, error: ServiceError) -> JSONResponse:
        return error_response(error)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_: Request, error: RequestValidationError) -> JSONResponse:
        return error_response(ServiceError("invalid_filters", "request validation failed", 422))

    def authenticate(request: Request, token: Token) -> str:
        bearer = f"{token.scheme} {token.credentials}" if token else None
        return auth.authenticate(bearer, request.client.host if request.client else None)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "snapshot_id": str(snapshot_reader().snapshot)}

    routes = APIRouter(prefix="/v1", dependencies=[Depends(authenticate)])

    @routes.get("/coverage")
    def coverage() -> Envelope[list[Coverage]]:
        records = snapshot_reader().coverage()
        return Envelope(
            snapshot_id=snapshot_reader().snapshot,
            score_date=snapshot_reader().score_date,
            coverage=records,
            data=records,
        )

    @routes.get("/cves")
    def vulnerabilities(filters: FilterQuery) -> Envelope[list[Vulnerability]]:
        return snapshot_reader().vulnerabilities(filters)

    @routes.get("/cves/{cve_id}")
    def cve_detail(
        cve_id: FilterCve, snapshot_id: UUID, country_iso2: Country | None = None
    ) -> CveDetail:
        return detail(snapshot_reader(), cve_id, snapshot_id, country_iso2)

    @routes.get("/kpis")
    def risk(filters: FilterQuery) -> Envelope[RiskSummary]:
        return snapshot_reader().risk(filters)

    @routes.get("/map")
    def exposure(filters: FilterQuery) -> MapEnvelope:
        return snapshot_reader().geography(filters)

    @routes.get("/graph")
    def graph(filters: FilterQuery) -> Envelope[list[Edge]]:
        return snapshot_reader().graph(filters)

    @routes.get("/evidence/{evidence_id}")
    def evidence(evidence_id: EvidenceId) -> Envelope[Evidence]:
        return snapshot_reader().evidence(evidence_id)

    app.include_router(routes)
    v2 = APIRouter(prefix="/v2", dependencies=[Depends(authenticate)])
    if catalog is not None:

        @v2.get("/catalog")
        def official_catalog(filters: Annotated[CatalogFilters, Query()]) -> CatalogPage:
            return catalog_page(filters)

    if series is not None:

        @v2.get("/analytics/epss")
        def epss_history(filters: Annotated[SeriesFilters, Query()]) -> DailyRiskSeries:
            return risk_series(filters)

    if network is not None:

        @v2.get("/network")
        def annual_network_context(
            year: Annotated[int | None, Query(ge=1960, le=2100)] = None,
            country_alpha2: WdiAlpha2 | None = None,
        ) -> NetworkYear:
            return network_reader().year(year, country_alpha2)

    app.include_router(v2)
    if investigations is not None:
        from backend.investigations.routes import install

        install(app, auth, investigations, runtime=runtime)
    app.mount("/mcp", guarded_mcp)
    return app
