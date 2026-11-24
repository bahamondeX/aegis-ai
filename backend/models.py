from datetime import date
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, model_validator

from schemas.sources import CveId, Source

Country = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")]
EvidenceId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
FilterCve = Annotated[CveId, StringConstraints(max_length=32)]
Probability = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
Severity = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Filters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    cve_ids: tuple[FilterCve, ...] = Field(default=(), max_length=20)
    country_iso2: Country | None = None
    kev_only: bool = False
    min_epss: Probability | None = None
    severity: Severity | None = None
    date_from: date | None = None
    date_to: date | None = None
    limit: int = Field(default=50, ge=1, le=200)

    @model_validator(mode="after")
    def date_order(self) -> Self:
        if self.date_from and self.date_to:
            days = (self.date_to - self.date_from).days
            if not 0 <= days <= 3660:
                raise ValueError("date range must be ordered and at most 3660 days")
        return self


class Coverage(BaseModel):
    source: Source
    status: Literal["ok", "partial", "blocked", "unavailable"]
    row_count: int
    coverage: Probability | None
    source_date: AwareDatetime | None
    retrieved_at: AwareDatetime | None
    duration_ms: int
    error_code: str | None


class Vulnerability(BaseModel):
    cve_id: CveId
    description: str
    kev: bool
    kev_added_at: date
    severity: Severity | None
    cvss_score: float | None
    cvss_version: str | None
    cvss_source: str | None
    epss: Probability | None
    percentile: Probability | None
    score_date: date | None
    source_refs: list[EvidenceId]
    epss_evidence_id: EvidenceId | None


class RiskSummary(BaseModel):
    total_cves: int
    kev_cves: int
    with_nvd: int
    with_epss: int
    high_epss: int


class Edge(BaseModel):
    cve_id: CveId
    relation_type: str
    target_id: str
    target_label: str
    vendor: str | None
    evidence_id: EvidenceId


class Exposure(BaseModel):
    cve_id: CveId
    country_iso2: Country
    snapshot_at: AwareDatetime
    source: str
    scope: str
    count: int | None
    unit: str
    confidence: Probability | None
    coverage: Probability | None
    evidence_id: EvidenceId


class Evidence(BaseModel):
    evidence_id: EvidenceId
    source: Source
    source_record_id: str
    retrieved_at: AwareDatetime
    source_date: AwareDatetime
    checksum: EvidenceId
    uri: str
    license: str


class Envelope[T](BaseModel):
    snapshot_id: UUID
    score_date: date
    coverage: list[Coverage]
    cohort: Literal["cisa_kev"] = "cisa_kev"
    availability: Literal["available", "unavailable"] = "available"
    data: T


class ServiceError(Exception):
    def __init__(self, code: str, message: str, status: int) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
