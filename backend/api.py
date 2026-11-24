"""FastAPI and official MCP Streamable HTTP over one snapshot reader."""

import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Annotated
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
from backend.investigations.routes import install
from backend.investigations.service import InvestigationService
from backend.models import (
    Country,
    Coverage,
    CveDetail,
    Edge,
    Envelope,
    Evidence,
    EvidenceId,
    Exposure,
    Filters,
    MitigationVulnerability,
    RiskSummary,
    ServiceError,
    Vulnerability,
)
from backend.reader import SnapshotReader
from schemas.sources import CveId

FilterQuery = Annotated[Filters, Query()]
Token = Annotated[HTTPAuthorizationCredentials | None, Security(HTTPBearer(auto_error=False))]


def error_response(error: ServiceError) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if error.status == 401 else None
    return JSONResponse(
        {"error": {"code": error.code, "message": str(error)}},
        status_code=error.status,
        headers=headers,
    )


async def mcp_result[T](call: Callable[[], Envelope[T]]) -> Envelope[T]:
    try:
        return await anyio.to_thread.run_sync(call)
    except ServiceError as error:
        raise ToolError(json.dumps({"code": error.code, "message": str(error)})) from None


def create_app(
    reader: SnapshotReader,
    auth: Auth,
    investigations: InvestigationService | None = None,
    *,
    runtime: bool = False,
) -> FastAPI:
    mcp = FastMCP("AEGIS", stateless_http=True, json_response=True, streamable_http_path="/")

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
            ranked = reader.vulnerabilities(selection)
            records = []
            for row in ranked.data:
                text = (
                    guidance(reader, row.cve_id, row.source_refs[0])
                    if include_mitigation and row.kev and row.source_refs
                    else None
                )
                records.append(MitigationVulnerability(**row.model_dump(), mitigation=text))
            return reader.envelope(records, regional=selection.country_iso2 is not None)

        return await mcp_result(read)

    @mcp.tool()
    async def get_risk_summary(filters: Filters | None = None) -> Envelope[RiskSummary]:
        """Count the filtered cohort and its EPSS and NVD coverage."""
        return await mcp_result(lambda: reader.risk(filters or Filters()))

    @mcp.tool()
    async def get_exposure_by_country(filters: Filters | None = None) -> Envelope[list[Exposure]]:
        """Read verified geographic observations or report unavailable coverage."""
        return await mcp_result(lambda: reader.map(filters or Filters()))

    @mcp.tool()
    async def get_relationship_graph(filters: Filters | None = None) -> Envelope[list[Edge]]:
        """Read evidence-backed CVE to product and CWE relationships."""
        return await mcp_result(lambda: reader.graph(filters or Filters()))

    @mcp.tool()
    async def get_evidence(evidence_id: EvidenceId) -> Envelope[Evidence]:
        """Resolve a published evidence identifier to source provenance."""
        return await mcp_result(lambda: reader.evidence(evidence_id))

    @mcp.tool()
    async def propose_ui_filters(filters: Filters) -> Envelope[Filters]:
        """Return a typed proposal for the caller to review."""
        return await mcp_result(lambda: reader.envelope(filters))

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
        return {"status": "ok", "snapshot_id": str(reader.snapshot)}

    routes = APIRouter(prefix="/v1", dependencies=[Depends(authenticate)])

    @routes.get("/coverage")
    def coverage() -> Envelope[list[Coverage]]:
        records = reader.coverage()
        return Envelope(
            snapshot_id=reader.snapshot,
            score_date=reader.score_date,
            coverage=records,
            data=records,
        )

    @routes.get("/cves")
    def vulnerabilities(filters: FilterQuery) -> Envelope[list[Vulnerability]]:
        return reader.vulnerabilities(filters)

    @routes.get("/cves/{cve_id}")
    def cve_detail(
        cve_id: CveId, snapshot_id: UUID, country_iso2: Country | None = None
    ) -> CveDetail:
        return detail(reader, cve_id, snapshot_id, country_iso2)

    @routes.get("/kpis")
    def risk(filters: FilterQuery) -> Envelope[RiskSummary]:
        return reader.risk(filters)

    @routes.get("/map")
    def exposure(filters: FilterQuery) -> MapEnvelope:
        return reader.geography(filters)

    @routes.get("/graph")
    def graph(filters: FilterQuery) -> Envelope[list[Edge]]:
        return reader.graph(filters)

    @routes.get("/evidence/{evidence_id}")
    def evidence(evidence_id: EvidenceId) -> Envelope[Evidence]:
        return reader.evidence(evidence_id)

    app.include_router(routes)
    if investigations is not None:
        install(app, auth, investigations, runtime=runtime)
    app.mount("/mcp", guarded_mcp)
    return app
