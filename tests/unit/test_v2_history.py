"""Tests for gaps and model scopes in the V2 analytical history contract."""

from datetime import date, timedelta
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from pipelines.bronze import LocalBronze, artifact, ensure
from pipelines.io import DataError
from pipelines.v2_history import temporal_rows
from scripts.v2_epss_silver_bulk import missing_percentiles


def test_legacy_epss_receipt_recovers_real_null_count_from_parquet(tmp_path: Path) -> None:
    # Isolated synthetic fixture for a legacy receipt without a null count.
    file = tmp_path / "fixture.parquet"
    pq.write_table(pa.table({"percentile": [0.0, None, 0.2, None]}), file, row_group_size=2)
    store = LocalBronze(tmp_path / "bronze")
    ref, _ = ensure(store, artifact("epss", "normalized", file), file)
    assert missing_percentiles(store, ref, 4) == 2
    with pytest.raises(DataError, match="rows or schema"):
        missing_percentiles(store, ref, 5)


def test_rolling_measures_require_every_day_under_the_same_model():
    start = date(2026, 1, 1)
    days = [start + timedelta(days=i) for i in range(9)]
    rows = [
        {"score_date": day, "epss": i / 10, "percentile": None, "model_version": "v1"}
        for i, day in enumerate(days[:8])
    ]
    rows.append({"score_date": days[-1], "epss": 0.9, "percentile": None, "model_version": "v2"})
    result = temporal_rows(rows, days[6], days[-1], {d.isoformat() for d in days})
    assert result[0]["mean_7d"] == pytest.approx(0.3)
    assert result[1]["change_7d"] == pytest.approx(0.7)
    assert result[1]["volatility_7d"] == pytest.approx(0.2)
    assert result[-1]["model_transition"] is True
    assert result[-1]["change_1d"] is None
    assert result[-1]["change_7d"] is None
    assert result[-1]["mean_7d"] is None


def test_missing_source_and_unscored_cve_have_distinct_statuses():
    start = date(2026, 1, 1)
    end = start + timedelta(days=2)
    rows = [{"score_date": start, "epss": 0.0, "percentile": None, "model_version": "v1"}]
    result = temporal_rows(rows, start, end, {start.isoformat(), end.isoformat()})
    assert [row["status"] for row in result] == ["observed", "source_absent", "cve_unscored"]
    assert result[0]["epss"] == 0.0
    assert result[0]["percentile"] is None
    assert result[0]["change_1d"] is None
