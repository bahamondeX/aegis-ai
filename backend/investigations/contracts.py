"""Wire contracts for investigation requests, reports, and SSE."""

from datetime import date
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints

from backend.models import Coverage, Edge, Evidence, EvidenceId, Exposure, Filters, RiskSummary
from schemas.sources import CveId

Node = Literal["plan", "research", "analyze", "validate"]
Mode = Literal["deterministic", "bedrock", "fallback"]
RegionScope = Literal["global", "country", "unsupported_region"]
RunStatus = Literal["completed", "failed", "cancelled", "interrupted"]


class Request(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    question: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=600)]
    filters: Filters = Field(default_factory=Filters)
    snapshot_id: UUID | None = None
    scope: Literal["global", "regional"] | None = None


class CancelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["cancel"]
    investigation_id: UUID


class Plan(BaseModel):
    filters: Filters
    scope: RegionScope


class Claim(BaseModel):
    key: str
    text: str
    evidence_ids: list[EvidenceId]


class Usage(BaseModel):
    model_id: str
    attempts: int = Field(ge=1, le=3)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    latency_ms: int = Field(ge=0)


class Report(BaseModel):
    snapshot_id: UUID
    score_date: date
    scope: RegionScope
    coverage: list[Coverage]
    claims: list[Claim]
    geographic_note: str
    recommendations: list[str]
    analysis_mode: Mode
    usage: list[Usage] = Field(default_factory=list)


class Started(BaseModel):
    snapshot_id: UUID
    trace_id: UUID


class NodeStarted(BaseModel):
    node: Node
    revision: int = Field(ge=0, le=1)


class EvidenceAdded(BaseModel):
    items: list[Evidence]


class FilterProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", json_schema_serialization_defaults_required=True)

    command: Literal["propose_filters"] = "propose_filters"
    snapshot_id: UUID
    filters: Filters


class Analytics(BaseModel):
    snapshot_id: UUID
    scope: RegionScope
    filters: Filters
    risk: RiskSummary | None = None
    ranked_cve_ids: list[CveId]
    graph: list[Edge]
    observations: list[Exposure]
    geography: Literal["available", "unavailable"]


class ErrorPayload(BaseModel):
    code: str
    message: str


class Completed(BaseModel):
    status: RunStatus


class EventBase(BaseModel):
    model_config = ConfigDict(extra="forbid", json_schema_serialization_defaults_required=True)

    version: Literal[1] = 1
    investigation_id: UUID
    seq: int = Field(ge=1)
    timestamp: AwareDatetime


class StartEvent(EventBase):
    type: Literal["investigation.started"] = "investigation.started"
    payload: Started


class NodeEvent(EventBase):
    type: Literal["node.started"] = "node.started"
    payload: NodeStarted


class EvidenceEvent(EventBase):
    type: Literal["evidence.added"] = "evidence.added"
    payload: EvidenceAdded


class ProposalEvent(EventBase):
    type: Literal["ui.filters.proposed"] = "ui.filters.proposed"
    payload: FilterProposal


class AnalyticsEvent(EventBase):
    type: Literal["analytics.updated"] = "analytics.updated"
    payload: Analytics


class ReportEvent(EventBase):
    type: Literal["report.completed"] = "report.completed"
    payload: Report


class ErrorEvent(EventBase):
    type: Literal["error"] = "error"
    payload: ErrorPayload


class DoneEvent(EventBase):
    type: Literal["done"] = "done"
    payload: Completed


Event = Annotated[
    StartEvent
    | NodeEvent
    | EvidenceEvent
    | ProposalEvent
    | AnalyticsEvent
    | ReportEvent
    | ErrorEvent
    | DoneEvent,
    Field(discriminator="type"),
]
