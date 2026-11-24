from datetime import date
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    StringConstraints,
    model_serializer,
    model_validator,
)

from schemas.geography import known_country
from schemas.sources import CveId, Source

Country = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$"), AfterValidator(known_country)]
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


class Advisory(BaseModel):
    text: str = Field(min_length=1, max_length=600)
    evidence_id: EvidenceId
    source: Literal["cisa"]


class MitigationVulnerability(Vulnerability):
    mitigation: Advisory | None = None

    @model_serializer(mode="wrap")
    def omit_absent_mitigation(self, handler: SerializerFunctionWrapHandler) -> Any:
        value = handler(self)
        if self.mitigation is None:
            value.pop("mitigation", None)
        return value


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


class GeographyCoverage(BaseModel):
    state: Literal["unavailable", "measured_zero", "observed"]
    category: Literal["observed_exposure", "sensor_attempt", "confirmed_incident"]
    country_iso2: Country | None = None
    reason: str | None = None
    count: int | None = Field(default=None, ge=0)
    precision: Literal["country", "region"] | None = None
    unit: str | None = None
    window_start: AwareDatetime | None = None
    window_end: AwareDatetime | None = None
    evidence_id: EvidenceId | None = None

    @model_validator(mode="after")
    def check_state(self) -> Self:
        if self.state == "unavailable":
            if self.count is not None or not self.reason:
                raise ValueError("unavailable geography requires a reason and no count")
        elif (
            self.count is None
            or (self.state == "measured_zero") != (self.count == 0)
            or not all(
                (self.precision, self.unit, self.window_start, self.window_end, self.evidence_id)
            )
            or self.window_start is None
            or self.window_end is None
            or self.window_end < self.window_start
        ):
            raise ValueError("measured geography requires an explicit value, window and evidence")
        return self


class Applicability(BaseModel):
    vendor: str
    product: str
    version: str | None = None
    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None
    configuration_path: str
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


class CveDetail(BaseModel):
    snapshot_id: UUID
    vulnerability: Vulnerability
    products: list[Edge]
    applicability: list[Applicability]
    evidence: list[Evidence]
    geography: GeographyCoverage
    observations: list[Exposure]
    mitigation: Advisory | None = None


class ServiceError(Exception):
    def __init__(self, code: str, message: str, status: int) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
