"""Bounded reads from the release-pinned V2 catalog mart."""

from datetime import datetime
from functools import lru_cache
from typing import Literal

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq
from pydantic import BaseModel, ConfigDict, Field

from backend.models import FilterCve, ServiceError
from pipelines.bronze import PREFIX, BronzeStore, ObjectRef, materialized, record
from pipelines.epss_bronze import HEX, plan_id
from pipelines.io import DataError

GOLD_PREFIX = f"{PREFIX}/manifests/cve-catalog-gold"


class CatalogItem(BaseModel):
    cve_id: FilterCve
    year: int
    earliest_publication: datetime | None
    latest_modification: datetime | None
    in_kev: bool
    has_cvss: bool
    has_cwe: bool
    has_cpe: bool
    has_ssvc: bool
    sources: list[Literal["cve", "kev", "nvd"]]


class CatalogPage(BaseModel):
    release_id: str
    silver_snapshot: str
    year: int
    years: list[int]
    records_in_year: int
    total_distinct_cves: int
    next_after: FilterCve | None
    data: list[CatalogItem]


class CatalogFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    year: int | None = Field(default=None, ge=1990, le=2100)
    limit: int = Field(default=50, ge=1, le=100)
    after: FilterCve | None = None
    cve_id: FilterCve | None = None


class CatalogReader:
    def __init__(self, store: BronzeStore, component: str, release_id: str) -> None:
        if not HEX.fullmatch(component) or not HEX.fullmatch(release_id):
            raise DataError("invalid catalog component or release identifier")
        published = record(store, f"{GOLD_PREFIX}/{component}/committed.json")
        if not published or published["release_id"] != release_id:
            raise DataError("reviewed catalog mart is unavailable")
        manifest = published["manifest"]
        if plan_id(manifest) != release_id or manifest["schema_version"] != 1:
            raise DataError("catalog release digest or schema differs from the reviewed manifest")
        self.store, self.release_id, self.manifest = store, release_id, manifest
        self.years: list[int] = sorted(int(year) for year in manifest["shards"])
        if not self.years or len(self.years) > 100:
            raise DataError("catalog manifest contains an unexpected year index")

    @lru_cache(maxsize=2)
    def shard(self, year: int) -> pa.Table:
        entry = self.manifest["shards"][str(year)]
        ref = ObjectRef(**entry["object"])
        if not 0 < ref.size <= 8 * 1024**2 or not ref.key.startswith(
            f"{PREFIX}/vulnerabilities/catalog/"
        ):
            raise DataError("catalog object is outside its approved location or size")
        with materialized(self.store, ref) as file:
            parquet = pq.ParquetFile(file)
            if not 0 < parquet.metadata.num_rows == entry["count"] <= 100_000:
                raise DataError("catalog mart row count differs from the reviewed shard")
            return parquet.read()

    def page(
        self,
        year: int | None,
        *,
        limit: int,
        after: str | None = None,
        cve_id: str | None = None,
    ) -> CatalogPage:
        if not 1 <= limit <= 100:
            raise ServiceError("invalid_filters", "Catalog page limit must be 1 through 100", 422)
        target = year if year is not None else int(cve_id[4:8]) if cve_id else self.years[-1]
        if cve_id and (after or target != int(cve_id[4:8])):
            raise ServiceError(
                "invalid_filters", "The CVE search and requested year do not agree", 422
            )
        if after and target != int(after[4:8]):
            raise ServiceError("invalid_filters", "The page cursor belongs to another year", 422)
        entry = self.manifest["shards"].get(str(target))
        results = []
        if entry:
            table = self.shard(target)
            if cve_id:
                table = table.filter(pc.equal(table["cve_id"], cve_id))
            if after:
                table = table.filter(pc.greater(table["cve_id"], after))
            results = table.slice(0, limit + 1).to_pylist()
        rows = [CatalogItem.model_validate(item) for item in results[:limit]]
        return CatalogPage(
            release_id=self.release_id,
            silver_snapshot=str(self.manifest["silver_snapshot"]),
            year=target,
            years=self.years,
            records_in_year=entry["count"] if entry else 0,
            total_distinct_cves=self.manifest["distinct_cves"],
            next_after=rows[-1].cve_id if len(results) > limit else None,
            data=rows,
        )
