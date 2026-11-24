"""Release-pinned annual mobile subscription observations from World Bank WDI."""

from collections import Counter
from datetime import date
from typing import Annotated, Literal

import pyarrow.parquet as pq
from pydantic import BaseModel, Field, FiniteFloat, StrictInt, StringConstraints, model_validator

from backend.models import Country, ServiceError
from pipelines.bronze import PREFIX, BronzeStore, ObjectRef, materialized, record
from pipelines.epss_bronze import HEX, plan_id
from pipelines.io import DataError
from pipelines.wdi_context import INDICATOR, INDICATOR_PAGE
from schemas.geography import known_country

WdiAlpha2 = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")]


class Economy(BaseModel):
    economy_code: str = Field(pattern=r"^[A-Z]{3}$")
    alpha2: WdiAlpha2
    name: str = Field(min_length=1, max_length=150)
    region_code: str
    region_name: str
    canonical_iso2: Country | None = None

    @model_validator(mode="after")
    def canonical_country(self) -> "Economy":
        try:
            self.canonical_iso2 = known_country(self.alpha2)
        except ValueError:
            self.canonical_iso2 = None
        return self


class AnnualValue(BaseModel):
    economy_code: str = Field(pattern=r"^[A-Z]{3}$")
    year: StrictInt = Field(ge=1960, le=2100)
    indicator: Literal["IT.CEL.SETS.P2"]
    subscriptions_per_100_people: FiniteFloat | None = Field(ge=0)


class SeriesValue(BaseModel):
    economy: Economy
    value: FiniteFloat | None
    availability: Literal["observed", "measured_zero", "unavailable"]


class NetworkYear(BaseModel):
    release_id: str
    year: int
    available_years: list[int]
    country_alpha2: WdiAlpha2 | None
    source: Literal["World Bank WDI / ITU"] = "World Bank WDI / ITU"
    series: Literal["IT.CEL.SETS.P2"] = INDICATOR
    citation: str = INDICATOR_PAGE
    source_date: date
    unit: Literal["mobile cellular subscriptions per 100 people"] = (
        "mobile cellular subscriptions per 100 people"
    )
    geographic_basis: Literal["reported_economy_subscription_rate"] = (
        "reported_economy_subscription_rate"
    )
    granularity: Literal["year"] = "year"
    license: Literal["CC BY 4.0"] = "CC BY 4.0"
    economies_in_scope: int
    economies_with_values: int
    data: list[SeriesValue]


def release_key(digest: str) -> str:
    if not HEX.fullmatch(digest):
        raise DataError("invalid WDI network release digest")
    return f"{PREFIX}/manifests/network-releases/{digest}.json"


def rows(store: BronzeStore, value: dict, *, max_rows: int) -> list[dict]:
    ref = ObjectRef(**value)
    if not ref.key.startswith(f"{PREFIX}/network/") or ref.size > 2 * 1024**2:
        raise DataError("unexpected WDI artifact size or prefix")
    with materialized(store, ref) as file:
        table = pq.ParquetFile(file)
        if table.metadata.num_rows > max_rows:
            raise DataError("WDI projection exceeds its row budget")
        return table.read().to_pylist()


class NetworkContextReader:
    def __init__(
        self,
        release_id: str,
        source_date: date,
        countries: list[Economy],
        observations: list[AnnualValue],
        expected_counts: dict,
    ) -> None:
        self.release_id, self.source_date = release_id, source_date
        self.countries = {entry.economy_code: entry for entry in countries}
        self.by_iso = {entry.alpha2: entry for entry in countries}
        self.data = {
            (point.economy_code, point.year): point.subscriptions_per_100_people
            for point in observations
        }
        self.counts = Counter(
            year for (economy, year), value in self.data.items() if value is not None
        )
        if (
            len(countries) != len(self.countries)
            or len(self.by_iso) != len(countries)
            or len(observations) != len(self.data)
            or any(code not in self.countries for code, _ in self.data)
            or len(countries) != expected_counts["country_dimension_rows"]
            or len(observations) != expected_counts["normalized_observation_rows"]
            or dict(self.counts)
            != {
                int(year): amount
                for year, amount in expected_counts["country_coverage_by_year"].items()
            }
            or not self.counts
        ):
            raise DataError("WDI coverage does not reconcile with the source receipt")
        self.latest_year = max(self.counts)

    @classmethod
    def load(cls, store: BronzeStore, release_id: str) -> "NetworkContextReader":
        manifest = record(store, release_key(release_id))
        if (
            not manifest
            or plan_id(manifest) != release_id
            or manifest["schema_version"] != 1
            or manifest["indicator"] != INDICATOR
            or manifest["license"] != "CC BY 4.0"
        ):
            raise DataError("verified WDI network release is unavailable")
        countries = [
            Economy.model_validate(row) for row in rows(store, manifest["dimension"], max_rows=300)
        ]
        facts = [
            AnnualValue.model_validate(row)
            for row in rows(store, manifest["observations"], max_rows=20_000)
        ]
        return cls(
            release_id,
            date.fromisoformat(manifest["source_date"]),
            countries,
            facts,
            manifest["counts"],
        )

    def year(self, year: int | None = None, country: str | None = None) -> NetworkYear:
        target_year = self.latest_year if year is None else year
        if country and country not in self.by_iso:
            raise ServiceError(
                "unknown_economy", "No WDI economy matches the selected country code", 404
            )
        selected = [self.by_iso[country]] if country else list(self.countries.values())
        data = []
        for item in sorted(selected, key=lambda row: row.alpha2):
            value = self.data.get((item.economy_code, target_year))
            data.append(
                SeriesValue(
                    economy=item,
                    value=value,
                    availability="unavailable"
                    if value is None
                    else "measured_zero"
                    if value == 0
                    else "observed",
                )
            )
        return NetworkYear(
            release_id=self.release_id,
            year=target_year,
            available_years=sorted(self.counts),
            country_alpha2=country,
            source_date=self.source_date,
            economies_in_scope=len(data),
            economies_with_values=sum(row.value is not None for row in data),
            data=data,
        )
