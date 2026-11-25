"""Read source-specific vulnerability profiles from bounded, version-pinned ranges."""

import io
import json
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from typing import Literal

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq
from pydantic import BaseModel, JsonValue

from backend.models import FilterCve, ServiceError
from pipelines.bronze import PREFIX, ObjectRef, S3Bronze, materialized, record
from pipelines.epss_bronze import HEX, plan_id
from pipelines.io import DataError, digest

INDEX_PREFIX = f"{PREFIX}/manifests/cve-profile-index"
ROW_GROUP_LIMIT = 512
RANGE_LIMIT = 48 * 1024**2


@dataclass
class ProfileBudget:
    bytes_read: int = 0
    requests: int = 0
    byte_limit: int = RANGE_LIMIT
    request_limit: int = 32


class VersionedRanges(io.RawIOBase):
    def __init__(self, store: S3Bronze, ref: ObjectRef, budget: ProfileBudget) -> None:
        super().__init__()
        if not ref.version_id or not ref.size:
            raise DataError("source records require an exact S3 object version")
        self.store, self.ref, self.budget = store, ref, budget
        self.offset = 0

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.offset

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self.offset, io.SEEK_END: self.ref.size}[whence]
        if not 0 <= base + offset <= self.ref.size:
            raise OSError("source seek is outside the committed object")
        self.offset = base + offset
        return self.offset

    def read(self, size: int | None = -1) -> bytes:
        if self.closed:
            raise ValueError("source object is closed")
        available = self.ref.size - self.offset
        length = available if size is None or size < 0 else min(size, available)
        if not length:
            return b""
        self.budget.bytes_read += length
        self.budget.requests += 1
        if (
            self.budget.bytes_read > self.budget.byte_limit
            or self.budget.requests > self.budget.request_limit
        ):
            raise ServiceError("profile_budget", "Source range budget exceeded", 413)
        interval = f"{self.offset}-{self.offset + length - 1}"
        result = self.store.client.get_object(
            **self.store.parameters(self.ref.key),
            VersionId=self.ref.version_id,
            Range=f"bytes={interval}",
        )
        with result["Body"] as stream:
            if (
                result.get("VersionId") != self.ref.version_id
                or result.get("ContentRange") != f"bytes {interval}/{self.ref.size}"
                or result.get("ContentLength") != length
                or result.get("ServerSideEncryption") != "aws:kms"
                or result.get("SSEKMSKeyId") != self.store.kms_key
            ):
                raise DataError("source range failed version or encryption verification")
            value = stream.read(length + 1)
        if len(value) != length:
            raise DataError("source range returned an unexpected number of bytes")
        self.offset += length
        return value


class SourceRecord(BaseModel):
    source: Literal["cve", "nvd", "kev"]
    capture: str
    evidence_id: str
    source_url: str
    published_at: datetime | None
    modified_at: datetime | None
    status: str | None
    descriptions: list[JsonValue]
    assessments: JsonValue = None
    weaknesses: JsonValue = None
    applicability: JsonValue = None
    references: JsonValue = None
    containers: JsonValue = None
    required_action: str | None = None
    kev_added: str | None = None


class VulnerabilityProfile(BaseModel):
    release_id: str
    cve_id: FilterCve
    source_records: list[SourceRecord]
    geographic_coverage: Literal["unavailable"] = "unavailable"


def source_record(cve: str, capture: str, ref: ObjectRef, row: dict) -> SourceRecord:
    source = capture.split("/")[0]
    payload = json.loads(row["payload"])
    fields = {
        "source": source,
        "capture": capture,
        "evidence_id": digest(f"{cve}/{capture}/{ref.sha256}".encode()),
        "published_at": row["published_at"],
        "modified_at": row["modified_at"],
        "status": row["status"],
    }
    if source == "nvd":
        item = payload["cve"]
        if item["id"] != cve:
            raise DataError("NVD payload does not match the requested CVE")
        fields.update(
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve}",
            descriptions=item.get("descriptions", []),
            assessments=item.get("metrics"),
            weaknesses=item.get("weaknesses"),
            applicability=item.get("configurations"),
            references=item.get("references"),
        )
    elif source == "cve":
        if payload["cveMetadata"]["cveId"] != cve:
            raise DataError("CVE Program payload does not match the requested CVE")
        containers = payload["containers"]
        cna = containers.get("cna", {})
        fields.update(
            source_url=f"https://www.cve.org/CVERecord?id={cve}",
            descriptions=cna.get("descriptions", []),
            assessments=cna.get("metrics"),
            weaknesses=cna.get("problemTypes"),
            applicability=cna.get("affected"),
            references=cna.get("references"),
            containers=containers,
        )
    else:
        if source != "kev" or payload["cveID"] != cve:
            raise DataError("CISA payload does not match the requested CVE")
        fields.update(
            source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            descriptions=[{"lang": "en", "value": payload.get("shortDescription", "")}],
            required_action=payload.get("requiredAction"),
            kev_added=payload.get("dateAdded"),
        )
    return SourceRecord.model_validate(fields)


class ProfileReader:
    def __init__(self, store: S3Bronze, component: str, release: str) -> None:
        if not HEX.fullmatch(component) or not HEX.fullmatch(release):
            raise DataError("invalid profile component or release ID")
        published = record(store, f"{INDEX_PREFIX}/{component}/committed.json")
        if (
            not published
            or published["index_id"] != release
            or plan_id(published["manifest"]) != release
        ):
            raise DataError("the reviewed profile index is unavailable")
        self.store, self.release, self.manifest = store, release, published["manifest"]
        if self.manifest["schema_version"] != 1 or self.manifest["catalog_component"] != component:
            raise DataError("profile index does not match its approved layout")

    @lru_cache(maxsize=2)
    def _year(self, year: str) -> pa.Table:
        entry = self.manifest["years"][year]
        ref = ObjectRef(**entry["object"])
        if (
            not ref.key.startswith(f"{PREFIX}/vulnerabilities/profile-index/")
            or ref.size > 8 * 1024**2
        ):
            raise DataError("profile year object is outside the approved scope")
        with materialized(self.store, ref) as file:
            parquet = pq.ParquetFile(file)
            if not 0 < parquet.metadata.num_rows == entry["count"] <= 100_000:
                raise DataError("profile index row count differs from the release")
            return parquet.read()

    @lru_cache(maxsize=64)
    def profile(self, cve: str) -> VulnerabilityProfile:
        year = cve[4:8]
        if year not in self.manifest["years"]:
            raise ServiceError("not_found", "No official records match this CVE", 404)
        table = self._year(year)
        located = table.filter(pc.equal(table["cve_id"], cve)).to_pylist()
        if not located:
            raise ServiceError("not_found", "No official records match this CVE", 404)
        if len(located) != 1 or not 0 < len(located[0]["locations"]) <= 8:
            raise DataError("profile lookup has an unexpected number of records")
        budget, records = ProfileBudget(), []
        for item in sorted(located[0]["locations"], key=lambda row: row["capture"]):
            capture, group = item["capture"], item["row_group"]
            source = capture.split("/")[0]
            prefix = "cve-program" if source == "cve" else source
            ref = ObjectRef(**self.manifest["sources"][capture])
            if not ref.key.startswith(f"{PREFIX}/{prefix}/normalized/"):
                raise DataError("profile source points outside its approved prefix")
            with VersionedRanges(self.store, ref, budget) as file:
                parquet = pq.ParquetFile(file)
                if not 0 <= group < parquet.num_row_groups <= ROW_GROUP_LIMIT:
                    raise DataError("profile row group is incompatible with verified source")
                chunk = parquet.read_row_group(
                    group, columns=["cve_id", "published_at", "modified_at", "status", "payload"]
                )
                found = chunk.filter(pc.equal(chunk["cve_id"], cve)).to_pylist()
            if len(found) != 1:
                raise DataError("source range differs from its reviewed CVE index")
            records.append(source_record(cve, capture, ref, found[0]))
        profile = VulnerabilityProfile(release_id=self.release, cve_id=cve, source_records=records)
        if len(profile.model_dump_json().encode()) > 512 * 1024:
            raise ServiceError("profile_budget", "Profile exceeds the response budget", 413)
        return profile
