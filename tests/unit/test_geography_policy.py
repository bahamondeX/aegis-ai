"""Isolated validation cases. These payloads are never published."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from backend.investigations.contracts import Request
from backend.models import Filters, GeographyCoverage


def test_country_and_date_scope_validation() -> None:
    assert Filters(country_iso2="PE").country_iso2 == "PE"
    assert Filters(country_iso2="CA").country_iso2 == "CA"
    for invalid in [
        {"country_iso2": "ZZ"},
        {"country_iso2": "South America"},
        {"region": "Ontario"},
        {"date_from": "2026-10-01", "date_to": "2026-09-01"},
        {"limit": 201},
    ]:
        with pytest.raises(ValidationError):
            Filters.model_validate(invalid)


def test_missing_and_measured_zero_are_distinct_and_categories_are_closed() -> None:
    missing = GeographyCoverage(
        state="unavailable", category="observed_exposure", reason="collector unavailable"
    )
    assert missing.count is None
    with pytest.raises(ValidationError):
        GeographyCoverage(
            state="unavailable", category="observed_exposure", reason="missing", count=0
        )
    with pytest.raises(ValidationError):
        GeographyCoverage(state="measured_zero", category="observed_exposure", count=0)
    stamp = datetime(2025, 1, 1, tzinfo=UTC)
    zero = {
        "state": "measured_zero",
        "count": 0,
        "unit": "services",
        "precision": "country",
        "window_start": stamp,
        "window_end": stamp,
        "evidence_id": "a" * 64,
        "country_iso2": "PE",
    }
    categories = ("observed_exposure", "sensor_attempt", "confirmed_incident")
    for label in categories:
        value = GeographyCoverage.model_validate({**zero, "category": label})
        assert value.category == label and value.count == 0
    for category in ("network_coverage", "attempt_equals_incident", "asn_registration"):
        with pytest.raises(ValidationError):
            GeographyCoverage.model_validate({**zero, "category": category})


def test_mitigation_requires_matching_snapshot_and_explicit_single_cve() -> None:
    fields = {
        "question": "Review mitigation",
        "mitigation": {"cve_id": "CVE-2014-0160", "evidence_ids": ["a" * 64]},
    }
    with pytest.raises(ValidationError):
        Request.model_validate(fields)
    with pytest.raises(ValidationError):
        Request.model_validate(
            {
                **fields,
                "snapshot_id": "00000000-0000-4000-b000-000000000000",
                "filters": {"country_iso2": "PE", "cve_ids": ["CVE-2014-6271"]},
            }
        )
