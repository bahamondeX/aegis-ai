"""Snapshot-bound MCP reads and evidence validation."""

import asyncio
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from pydantic import BaseModel, ValidationError
from starlette.types import ASGIApp

from backend.investigations.contracts import Analytics, Claim, Plan, Request
from backend.investigations.timing import measure
from backend.models import (
    Advisory,
    Coverage,
    Edge,
    Envelope,
    Evidence,
    Exposure,
    Filters,
    MitigationVulnerability,
    RiskSummary,
    ServiceError,
    Vulnerability,
)

TOOLS = frozenset(
    {
        "get_vulnerabilities",
        "get_risk_summary",
        "get_exposure_by_country",
        "get_relationship_graph",
        "get_evidence",
        "propose_ui_filters",
    }
)
MAX_EVIDENCE = 12
MAX_RANKED = 3
GLOBAL_QUESTION = re.compile(
    r"^(?:prioritize|rank|summarize|list) (?:the )?(?:known exploited |global |top )?"
    r"(?:vulnerabilities|cves|risk)(?:\s*[?.])?$",
    re.IGNORECASE,
)


class Research(BaseModel):
    snapshot: UUID
    vulnerabilities: Envelope[list[Vulnerability]]
    risk: Envelope[RiskSummary] | None = None
    graph: Envelope[list[Edge]] | None = None
    geography: Envelope[list[Exposure]]
    proposal: Envelope[Filters] | None = None
    evidence: list[Evidence]
    mitigation: Advisory | None = None

    @property
    def coverage(self) -> list[Coverage]:
        return self.geography.coverage


def plan_request(request: Request) -> Plan:
    filters = request.filters.model_copy(update={"limit": min(request.filters.limit, MAX_RANKED)})
    if request.mitigation:
        return Plan(
            filters=filters.model_copy(update={"limit": 1}),
            scope="country" if filters.country_iso2 else "global",
            mitigation=request.mitigation,
        )
    if filters.country_iso2:
        return Plan(filters=filters, scope="country")
    if request.scope == "regional" or re.search(
        r"\b(country|countries|geograph\w*|regional|region|exposure|peru|lima|brazil|"
        r"north america|south america|europe|asia|africa|américa del sur|exposición)\b",
        request.question,
        re.IGNORECASE,
    ):
        return Plan(filters=filters, scope="unsupported_region")
    scope = (
        "global"
        if request.scope == "global" or GLOBAL_QUESTION.fullmatch(request.question)
        else "unsupported_region"
    )
    return Plan(filters=filters, scope=scope)


@asynccontextmanager
async def connect_tools(
    app: ASGIApp, authorization: str, client_ip: str
) -> AsyncIterator[ClientSession]:
    transport = httpx.ASGITransport(app=app, client=(client_ip, 0))
    async with httpx.AsyncClient(
        transport=transport,
        headers={"Authorization": authorization, "Host": "127.0.0.1:80"},
        trust_env=False,
    ) as client:
        async with streamable_http_client(
            "http://127.0.0.1:80/mcp/", http_client=client
        ) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                async with asyncio.timeout(5):
                    await session.initialize()
                yield session


async def investigate_tools(session: ClientSession, snapshot: UUID, plan: Plan) -> Research:
    slots = asyncio.Semaphore(2)
    baseline: tuple[Any, ...] | None = None

    async def call[T](name: str, args: dict, result: type[Envelope[T]]) -> Envelope[T]:
        nonlocal baseline
        if name not in TOOLS:
            raise ServiceError("invalid_tool", "tool is outside the investigation allowlist", 500)
        async with slots, asyncio.timeout(8):
            with measure("mcp." + name):
                reply = await session.call_tool(name, args)
        if reply.isError:
            raise ServiceError("tool_failure", "an evidence query failed", 503)
        try:
            value = result.model_validate(reply.structuredContent)
        except ValidationError:
            raise ServiceError("invalid_tool_response", "invalid evidence envelope", 503) from None
        seen = (value.snapshot_id, value.score_date, value.coverage)
        if value.snapshot_id != snapshot or (baseline is not None and seen != baseline):
            raise ServiceError(
                "snapshot_mismatch", "evidence snapshot and coverage must agree", 409
            )
        baseline = seen
        return value

    filters = {"filters": plan.filters.model_dump(mode="json")}
    if plan.mitigation:
        context = plan.mitigation
        # This is an exact CVE advisory lookup independent of geography or cohort eligibility.
        singleton = Filters(cve_ids=(context.cve_id,), limit=1)
        geo = await call("get_exposure_by_country", filters, Envelope[list[Exposure]])
        exact = await call(
            "get_vulnerabilities",
            {"filters": singleton.model_dump(mode="json"), "include_mitigation": True},
            Envelope[list[MitigationVulnerability]],
        )
        if len(exact.data) != 1 or exact.data[0].cve_id != context.cve_id:
            raise ServiceError("invalid_scope", "CVE is outside the selected release", 409)
        (item,) = exact.data
        allowed = list(dict.fromkeys(filter(None, (*item.source_refs, item.epss_evidence_id))))
        if not set(context.evidence_ids) <= set(allowed) or len(allowed) > MAX_EVIDENCE:
            raise ServiceError("invalid_evidence", "evidence is outside the selected CVE", 409)
        fetched = []
        for identifier in allowed:
            record = (
                await call("get_evidence", {"evidence_id": identifier}, Envelope[Evidence])
            ).data
            if record.evidence_id != identifier:
                raise ServiceError("invalid_evidence", "evidence ID differs from lookup", 409)
            fetched.append(record)
        if item.mitigation and not any(
            row.evidence_id == item.mitigation.evidence_id
            and row.source == "cisa"
            and row.source_record_id == context.cve_id
            for row in fetched
        ):
            raise ServiceError(
                "invalid_evidence", "catalog guidance lacks matching provenance", 409
            )
        return Research(
            snapshot=snapshot,
            vulnerabilities=Envelope[list[Vulnerability]].model_validate(exact.model_dump()),
            geography=geo,
            evidence=fetched,
            mitigation=item.mitigation,
        )

    if plan.scope == "unsupported_region":
        geo = await call("get_exposure_by_country", filters, Envelope[list[Exposure]])
        return Research(
            snapshot=snapshot,
            vulnerabilities=Envelope(
                snapshot_id=snapshot,
                score_date=geo.score_date,
                coverage=geo.coverage,
                availability="unavailable",
                data=[],
            ),
            geography=geo.model_copy(update={"data": [], "availability": "unavailable"}),
            evidence=[],
        )

    async with asyncio.TaskGroup() as queries:
        vulnerabilities_query = queries.create_task(
            call("get_vulnerabilities", filters, Envelope[list[Vulnerability]])
        )
        risk_query = queries.create_task(call("get_risk_summary", filters, Envelope[RiskSummary]))
        geography_query = queries.create_task(
            call("get_exposure_by_country", filters, Envelope[list[Exposure]])
        )
        graph_query = queries.create_task(
            call("get_relationship_graph", filters, Envelope[list[Edge]])
        )
        proposal_query = queries.create_task(call("propose_ui_filters", filters, Envelope[Filters]))
    vulnerabilities = vulnerabilities_query.result()
    risk = risk_query.result()
    geography = geography_query.result()
    graph = graph_query.result()
    proposal = proposal_query.result()
    if proposal.data != plan.filters:
        raise ServiceError("invalid_proposal", "tool returned filters outside the plan", 409)
    ranked = sorted(
        vulnerabilities.data,
        key=lambda row: (
            not row.kev,
            row.epss is None,
            -(row.epss or 0),
            row.cvss_score is None,
            -(row.cvss_score or 0),
            row.cve_id,
        ),
    )
    refs = [
        ref for row in ranked for ref in (*row.source_refs, row.epss_evidence_id) if ref is not None
    ]
    refs.extend(edge.evidence_id for edge in graph.data)
    refs.extend(row.evidence_id for row in geography.data)
    evidence_ids = list(dict.fromkeys(refs))[:MAX_EVIDENCE]
    async with asyncio.TaskGroup() as evidence_queries:
        lookups = [
            evidence_queries.create_task(
                call("get_evidence", {"evidence_id": identifier}, Envelope[Evidence])
            )
            for identifier in evidence_ids
        ]
    records = [lookup.result() for lookup in lookups]
    if any(
        identifier != record.data.evidence_id
        for identifier, record in zip(evidence_ids, records, strict=True)
    ):
        raise ServiceError("invalid_evidence", "evidence ID differs from its lookup key", 409)
    return Research(
        snapshot=snapshot,
        vulnerabilities=vulnerabilities.model_copy(update={"data": ranked}),
        risk=risk,
        graph=graph,
        geography=geography,
        proposal=proposal,
        evidence=[record.data for record in records],
    )


def supported_claims(research: Research) -> list[Claim]:
    """Render allowed facts directly from the typed data and matching evidence."""
    evidence = {value.evidence_id: value for value in research.evidence}
    claims: list[Claim] = []
    for row in research.vulnerabilities.data:
        cve = row.cve_id
        refs = [
            evidence[identifier]
            for identifier in row.source_refs
            if identifier in evidence and evidence[identifier].source_record_id == cve
        ]
        kev_ref = next((item for item in refs if item.source == "cisa"), None)
        nvd_ref = next((item for item in refs if item.source == "nvd"), None)
        epss_ref = evidence.get(row.epss_evidence_id or "")
        if row.kev and kev_ref:
            claims.append(
                Claim(
                    key=f"{cve}/kev",
                    text=f"CISA records known exploitation of {cve} in its KEV catalog.",
                    evidence_ids=[kev_ref.evidence_id],
                )
            )
        if (
            row.epss is not None
            and row.score_date
            and epss_ref
            and epss_ref.source == "epss"
            and epss_ref.source_date.date() == row.score_date
            and epss_ref.source_record_id.startswith(f"{row.score_date}/")
        ):
            claims.append(
                Claim(
                    key=f"{cve}/epss",
                    text=f"FIRST EPSS for {cve} on {row.score_date} is {row.epss:.5f}.",
                    evidence_ids=[epss_ref.evidence_id],
                )
            )
        if (
            row.cvss_score is not None
            and 0 <= row.cvss_score <= 10
            and row.cvss_version in {"2.0", "3.0", "3.1", "4.0"}
            and nvd_ref
        ):
            claims.append(
                Claim(
                    key=f"{cve}/cvss",
                    text=(
                        f"NVD reports a CVSS {row.cvss_version} base score "
                        f"of {row.cvss_score} for {cve}."
                    ),
                    evidence_ids=[nvd_ref.evidence_id],
                )
            )
    return claims


def analytics(research: Research, plan: Plan) -> Analytics:
    cited = {item.evidence_id: item for item in research.evidence}
    return Analytics(
        snapshot_id=research.snapshot,
        scope=plan.scope,
        filters=plan.filters,
        risk=research.risk.data
        if research.risk and research.risk.availability == "available"
        else None,
        ranked_cve_ids=[]
        if plan.mitigation
        else [row.cve_id for row in research.vulnerabilities.data],
        graph=[
            edge
            for edge in research.graph.data
            if edge.evidence_id in cited
            and cited[edge.evidence_id].source in {"cisa", "nvd"}
            and cited[edge.evidence_id].source_record_id == edge.cve_id
        ]
        if research.graph
        else [],
        observations=[
            row
            for row in research.geography.data
            if research.geography.availability == "available"
            and row.evidence_id in cited
            and cited[row.evidence_id].source == row.source
        ],
        geography=research.geography.availability,
    )
