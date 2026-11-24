"""Closed LangGraph orchestration. Model responses can select only verified claims."""

from collections.abc import Awaitable, Callable
from typing import Any, Literal, TypedDict
from uuid import UUID

from langgraph.graph import END, START, StateGraph
from mcp import ClientSession

from backend.investigations.bedrock import ModelSelection, Select
from backend.investigations.contracts import (
    Analytics,
    Claim,
    EvidenceAdded,
    EvidenceEvent,
    FilterProposal,
    Node,
    NodeEvent,
    NodeStarted,
    Plan,
    Report,
    Request,
    Usage,
)
from backend.investigations.research import (
    Research,
    analytics,
    investigate_tools,
    plan_request,
    supported_claims,
)
from backend.investigations.timing import measure
from backend.models import ServiceError

Emit = Callable[[type, Any], Awaitable[None]]
Checkpoint = Callable[[dict[str, Any]], Awaitable[None]]


class State(TypedDict, total=False):
    investigation_id: UUID
    user_id: str
    trace_id: UUID
    snapshot_id: UUID
    request: Request
    plan: Plan
    results: Research
    evidence_ids: list[str]
    selection: ModelSelection | None
    errors: list[str]
    usage: list[Usage]
    revision_count: int
    revise: bool
    report: Report


def geography_note(plan: Plan, results: Research) -> str:
    if plan.scope == "unsupported_region":
        return "Select a country or explicitly request a global investigation."
    if results.geography.availability == "unavailable":
        return "Verified geographic exposure is unavailable for this snapshot and scope."
    if not results.geography.data:
        return "The selected scope has no published observation or measured zero."
    return "Geographic observations are scoped to the source, snapshot and unit shown."


async def execute(
    state: State,
    session: ClientSession,
    select: Select | None,
    emit: Emit,
    checkpoint: Checkpoint,
) -> tuple[Report, Analytics, FilterProposal | None]:
    async def started(node: Node, current: State) -> None:
        await emit(NodeEvent, NodeStarted(node=node, revision=current.get("revision_count", 0)))

    async def plan(current: State) -> State:
        await started("plan", current)
        return {"plan": plan_request(current["request"])}

    async def research(current: State) -> State:
        await started("research", current)
        findings = await investigate_tools(session, current["snapshot_id"], current["plan"])
        if findings.evidence:
            await emit(EvidenceEvent, EvidenceAdded(items=findings.evidence))
        return {
            "results": findings,
            "evidence_ids": [item.evidence_id for item in findings.evidence],
        }

    async def analyze(current: State) -> State:
        await started("analyze", current)
        candidates = supported_claims(current["results"])
        if select is None or not candidates:
            return {"selection": None}
        try:
            with measure("bedrock.selection"):
                result = await select(candidates)
        except ServiceError as error:
            return {"selection": None, "errors": [*current.get("errors", []), error.code]}
        return {"selection": result.selection, "usage": [*current.get("usage", []), result.usage]}

    async def validate(current: State) -> State:
        await started("validate", current)
        findings = current["results"]
        scope = current["plan"]
        claims = supported_claims(findings)
        allowed = {claim.key for claim in claims}
        chosen = current.get("selection")
        errors = current.get("errors", [])
        used_model = bool(
            chosen and len(set(chosen.keys)) == len(chosen.keys) and set(chosen.keys) <= allowed
        )
        if select and claims and not used_model and not errors and current["revision_count"] == 0:
            return {"revision_count": 1, "revise": True}
        if used_model and chosen:
            claims = [claim for claim in claims if claim.key in chosen.keys]
        if scope.mitigation and findings.mitigation:
            guidance = findings.mitigation
            claims.append(
                Claim(
                    key=f"{scope.mitigation.cve_id}/mitigation",
                    text=f"CISA KEV required action: {guidance.text}",
                    evidence_ids=[guidance.evidence_id],
                )
            )
        if any(not set(claim.evidence_ids) <= set(current["evidence_ids"]) for claim in claims):
            raise ServiceError("ungrounded_report", "report failed evidence validation", 503)
        recommendations = (
            [
                "Check the cited advisories against your asset inventory and follow vendor "
                "remediation for confirmed affected assets."
            ]
            if claims
            else []
        )
        if scope.mitigation:
            recommendations = [
                "Confirm the product, deployed version, configuration and exposure in your "
                "authorized inventory before applying vendor guidance.",
                *(
                    []
                    if findings.mitigation
                    else [
                        "This release has no verified mitigation text. Review the citations and "
                        "ask your SOC or CSIRT to confirm applicable guidance."
                    ]
                ),
            ]
        return {
            "revise": False,
            "report": Report(
                snapshot_id=findings.snapshot,
                score_date=findings.vulnerabilities.score_date,
                scope=scope.scope,
                coverage=findings.coverage,
                claims=claims,
                geographic_note=geography_note(scope, findings),
                recommendations=recommendations,
                analysis_mode=(
                    "bedrock"
                    if used_model
                    else "fallback"
                    if select and claims
                    else "deterministic"
                ),
                usage=current.get("usage", []),
            ),
        }

    def next_node(current: State) -> Literal["research", "__end__"]:
        return "research" if current["revise"] else END

    graph = StateGraph(State)
    graph.add_node("plan", plan)
    graph.add_node("research", research)
    graph.add_node("analyze", analyze)
    graph.add_node("validate", validate)
    graph.add_edge(START, "plan")
    graph.add_edge("plan", "research")
    graph.add_edge("research", "analyze")
    graph.add_edge("analyze", "validate")
    graph.add_conditional_edges("validate", next_node)
    final = state
    async for step in graph.compile().astream(state, {"recursion_limit": 9}, stream_mode="values"):
        final = step
        if "plan" not in step:
            continue
        # Keep a durable stage boundary and provenance without storing the question or bearer.
        await checkpoint(
            {
                "revision": step["revision_count"],
                "plan": step["plan"].model_dump(mode="json"),
                "evidence_ids": step.get("evidence_ids", []),
                "has_report": "report" in step,
            }
        )
    result = final["results"]
    proposal = (
        FilterProposal(snapshot_id=result.snapshot, filters=result.proposal.data)
        if result.proposal
        else None
    )
    return final["report"], analytics(result, final["plan"]), proposal
