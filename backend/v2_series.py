"""Project globally aggregated daily EPSS observations from the committed Gold release."""

from datetime import date, timedelta
from typing import Literal

import pyarrow.parquet as pq
from pydantic import BaseModel, ConfigDict, Field, FiniteFloat

from backend.models import ServiceError
from pipelines.bronze import PREFIX, BronzeStore, ObjectRef, materialized, record
from pipelines.epss_bronze import HEX, plan_id
from pipelines.io import DataError


class DailyRisk(BaseModel):
    score_date: date
    model_version: str
    observed_count: int = Field(ge=1)
    missing_percentile_count: int = Field(ge=0)
    probability_at_least_095_count: int = Field(ge=0)
    mean_probability: FiniteFloat = Field(ge=0, le=1)
    approximate_median_probability: FiniteFloat = Field(ge=0, le=1)
    approximate_p95_probability: FiniteFloat = Field(ge=0, le=1)


class RiskDay(BaseModel):
    date: date
    observation: DailyRisk | None


class DailyRiskSeries(BaseModel):
    release_id: str
    snapshot_id: str
    source: Literal["FIRST EPSS"] = "FIRST EPSS"
    granularity: Literal["day"] = "day"
    scope: Literal["global"] = "global"
    quantile_method: Literal["Athena approx_percentile"] = "Athena approx_percentile"
    coverage_start: date
    coverage_end: date
    date_from: date
    date_to: date
    available_dates: int
    unavailable_dates: int
    data: list[RiskDay]


class SeriesFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    date_from: date | None = None
    date_to: date | None = None
    all_dates: bool = False


class RiskSeriesReader:
    def __init__(self, store: BronzeStore, campaign: str, release_id: str) -> None:
        if not HEX.fullmatch(campaign) or not HEX.fullmatch(release_id):
            raise DataError("invalid EPSS campaign or Gold release identifier")
        key = f"{PREFIX}/manifests/epss-silver-verification/{campaign}/full/committed.json"
        release = record(store, key)
        if (
            not release
            or plan_id(release) != release_id
            or release["probe"]
            or release["state"] != "passed"
        ):
            raise DataError("the fully reconciled EPSS Gold release is unavailable")
        self.release_id = release_id
        self.snapshot = str(release["snapshot"])
        self.start = date.fromisoformat(release["coverage_start"])
        self.end = date.fromisoformat(release["coverage_end"])
        ref = ObjectRef(
            release["mart_key"],
            release["mart_bytes"],
            release["mart_sha256"],
            release["mart_version"],
        )
        if ref.size > 1024**2 or not ref.key.startswith(f"{PREFIX}/epss/gold/"):
            raise DataError("the EPSS Gold object is outside its approved size or prefix")
        with materialized(store, ref) as file:
            parquet = pq.ParquetFile(file)
            if not 0 < parquet.metadata.num_rows == release["dates"] <= 2200:
                raise DataError("EPSS daily mart exceeds its approved row count")
            items = [DailyRisk.model_validate(row) for row in parquet.read().to_pylist()]
        self.days = {item.score_date: item for item in items}
        if (
            len(self.days) != len(items)
            or min(self.days) != self.start
            or max(self.days) != self.end
            or sum(item.observed_count for item in items) != release["rows"]
            or (self.end - self.start).days + 1 - len(self.days) != release["archive_absent_days"]
        ):
            raise DataError("the EPSS daily mart does not reconcile with its published release")

    def series(self, selection: SeriesFilters) -> DailyRiskSeries:
        if selection.all_dates and (selection.date_from or selection.date_to):
            raise ServiceError("invalid_filters", "Use an explicit date range or all dates", 422)
        end = selection.date_to or self.end
        start = selection.date_from or (
            self.start if selection.all_dates else max(self.start, end - timedelta(days=89))
        )
        if not self.start <= start <= end <= self.end or (end - start).days >= 2200:
            raise ServiceError(
                "invalid_filters", "The date range is outside this EPSS release", 422
            )
        dates = (start + timedelta(days=offset) for offset in range((end - start).days + 1))
        rows = [RiskDay(date=day, observation=self.days.get(day)) for day in dates]
        observed = sum(row.observation is not None for row in rows)
        return DailyRiskSeries(
            release_id=self.release_id,
            snapshot_id=self.snapshot,
            coverage_start=self.start,
            coverage_end=self.end,
            date_from=start,
            date_to=end,
            available_dates=observed,
            unavailable_dates=len(rows) - observed,
            data=rows,
        )
