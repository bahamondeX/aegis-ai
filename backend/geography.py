"""Public geography projections with separate network and vulnerability scope."""

from datetime import date
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, HttpUrl, ValidationError

from backend.models import Country, Envelope, EvidenceId, Exposure, GeographyCoverage, Probability
from pipelines.io import DataError, digest


class NetworkContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: EvidenceId
    kind: Literal["operational_presence", "published_coverage", "registration_country"]
    operator: str | None = Field(default=None, min_length=1, max_length=160)
    country_iso2: Country
    region: str | None = Field(default=None, max_length=100)
    scope: str = Field(min_length=1, max_length=280)
    source_date: date
    reporting_year: int | None = Field(default=None, ge=1900, le=2200)
    population_coverage: Probability | None = None
    retrieved_at: AwareDatetime
    publication: HttpUrl
    publisher: str
    license: str
    checksum: EvidenceId


CRTC_SHA = "b2872530eaba8207a8cc26e76031490365f51cb21dc7456b2251ad5ad04dddfa"
CRTC_PUBLICATION = "https://open.canada.ca/data/en/dataset/bd41f23a-6dbc-45ee-9419-422153aff567"


class ContextRelease(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1] = 1
    snapshot_id: UUID
    records: tuple[NetworkContext, ...] = Field(min_length=1, max_length=200)


def load_context(folder: Path, snapshot: UUID) -> tuple[NetworkContext, ...]:
    manifest, projection = (folder / name for name in ("manifest.json", "network-context.json"))
    if not manifest.exists() and not projection.exists():
        return ()
    try:
        # The separate manifest is immutable. It does not modify the lake publication.
        with manifest.open("rb") as file:
            entry = file.read(65)
        with projection.open("rb") as file:
            blob = file.read(128 * 1024 + 1)
    except OSError as exc:
        raise DataError("network context is incomplete") from exc
    return read_context(blob, entry, snapshot)


def read_context(blob: bytes, entry: bytes, snapshot: UUID) -> tuple[NetworkContext, ...]:
    if len(blob) > 128 * 1024 or entry != digest(blob).encode():
        raise DataError("network context checksum differs")
    try:
        result = ContextRelease.model_validate_json(blob)
    except ValidationError as exc:
        raise DataError("network context format is invalid") from exc
    if (
        result.snapshot_id != snapshot
        or len({row.record_id for row in result.records}) != len(result.records)
        or any(
            row.checksum != CRTC_SHA or str(row.publication) != CRTC_PUBLICATION
            for row in result.records
        )
    ):
        raise DataError("network context checksum, source or release does not match")
    return result.records


class NetworkLayer(BaseModel):
    state: Literal["available", "unavailable"]
    records: list[NetworkContext]
    note: str


class MapEnvelope(Envelope[list[Exposure]]):
    geography_version: Literal[1] = 1
    network: NetworkLayer
    exposure: GeographyCoverage


def unavailable_exposure(country: Country | None) -> GeographyCoverage:
    return GeographyCoverage(
        state="unavailable",
        category="observed_exposure",
        country_iso2=country,
        reason="No qualified CVE exposure source covers this release and scope.",
    )
