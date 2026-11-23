from datetime import UTC, date, datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    Field,
    StringConstraints,
    field_validator,
)


def utc_timestamp(value: str | datetime) -> datetime:
    stamp = datetime.fromisoformat(value) if isinstance(value, str) else value
    # NVD defines its offset-less API timestamps in UTC.
    return stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp.astimezone(UTC)


def normalize_cve(value: object) -> object:
    return value.strip().upper() if isinstance(value, str) else value


CveId = Annotated[
    str, BeforeValidator(normalize_cve), StringConstraints(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
]
Nonempty = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Score = Annotated[float, Field(ge=0, le=10, allow_inf_nan=False)]
Source = Literal["cisa", "epss", "nvd", "shodan"]
SCHEMA_VERSION = 1


class KevRecord(BaseModel):
    cveID: CveId
    vendorProject: Nonempty
    product: Nonempty
    shortDescription: Nonempty
    dateAdded: date
    dueDate: date
    knownRansomwareCampaignUse: Literal["Known", "Unknown"]
    cwes: list[str] = Field(default_factory=list)


class KevCatalog(BaseModel):
    catalogVersion: Nonempty
    dateReleased: AwareDatetime
    count: int = Field(gt=0)
    vulnerabilities: list[KevRecord]


class NvdText(BaseModel):
    lang: str
    value: Nonempty


class NvdWeakness(BaseModel):
    source: Nonempty
    description: list[NvdText]


class CvssData(BaseModel):
    version: Nonempty
    vectorString: Nonempty
    baseScore: Score
    baseSeverity: str | None = None


class CvssMetric(BaseModel):
    source: Nonempty
    type: str
    cvssData: CvssData
    baseSeverity: str | None = None


class NvdMetrics(BaseModel):
    cvssMetricV40: list[CvssMetric] = Field(default_factory=list)
    cvssMetricV31: list[CvssMetric] = Field(default_factory=list)
    cvssMetricV30: list[CvssMetric] = Field(default_factory=list)
    cvssMetricV2: list[CvssMetric] = Field(default_factory=list)

    def preferred(self) -> CvssMetric | None:
        for metrics in (
            self.cvssMetricV40,
            self.cvssMetricV31,
            self.cvssMetricV30,
            self.cvssMetricV2,
        ):
            if metrics:
                return min(
                    metrics,
                    key=lambda item: (
                        item.type != "Primary",
                        item.source,
                        item.cvssData.vectorString,
                    ),
                )
        return None


class NvdMatch(BaseModel):
    vulnerable: bool
    criteria: Nonempty
    matchCriteriaId: UUID


class NvdNode(BaseModel):
    cpeMatch: list[NvdMatch]


class NvdConfiguration(BaseModel):
    nodes: list[NvdNode]


class NvdRecord(BaseModel):
    id: CveId
    published: AwareDatetime
    lastModified: AwareDatetime
    descriptions: list[NvdText]
    metrics: NvdMetrics = Field(default_factory=NvdMetrics)
    weaknesses: list[NvdWeakness] = Field(default_factory=list)
    configurations: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("published", "lastModified", mode="before")
    @classmethod
    def normalize_timestamp(cls, value: str | datetime) -> datetime:
        return utc_timestamp(value)


class NvdWrapper(BaseModel):
    cve: NvdRecord


class NvdResponse(BaseModel):
    timestamp: AwareDatetime
    version: Literal["2.0"]
    startIndex: int
    totalResults: int = Field(ge=0)
    resultsPerPage: int = Field(ge=0)
    vulnerabilities: list[NvdWrapper]

    @field_validator("timestamp", mode="before")
    @classmethod
    def normalize_timestamp(cls, value: str | datetime) -> datetime:
        return utc_timestamp(value)


class Attempt(BaseModel):
    fetched_at: AwareDatetime
    http_status: int | None = None
    final_uri: str | None = None
    error_code: str | None = None
    retry_after_seconds: float | None = None


class Capture(BaseModel):
    schema_version: Literal[1] = SCHEMA_VERSION
    source: Source
    uri: Nonempty
    license: Nonempty
    attempts: list[Attempt] = Field(min_length=1)
    raw_file: str | None = None
    checksum: str | None = None
    source_date: AwareDatetime | None = None
    source_version: str | None = None
    error_code: str | None = None

    @property
    def retrieved_at(self) -> datetime:
        return self.attempts[-1].fetched_at


class Run(BaseModel):
    schema_version: Literal[1] = SCHEMA_VERSION
    run_id: UUID
    started_at: AwareDatetime
    finished_at: AwareDatetime
    captures: list[Capture]
    requested_nvd: list[CveId] = Field(max_length=20)
    nvd_found: list[CveId]
    cursor: list[CveId]
    nvd_history: list[UUID]
    epss_history: dict[date, UUID]
    shodan_status: str
    durations_ms: dict[Source, int]
