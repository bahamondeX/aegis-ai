"""Tests for gaps and model scopes in the V2 analytical history contract."""

from datetime import date, timedelta

import pytest

from pipelines.v2_history import temporal_rows


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
