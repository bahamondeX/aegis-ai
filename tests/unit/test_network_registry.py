"""Check ASN registration aggregation with isolated synthetic reports."""

from hashlib import sha256

import pytest

from pipelines.io import DataError
from pipelines.network_registry import analyze
from pipelines.wdi_context import INDICATOR, project

REPORT = (
    b"2|nro|20261123|4|19970101|20261123|+0000\n"
    b"nro|*|asn|*|3|summary\n"
    b"nro|*|ipv4|*|1|summary\n"
    b"arin|CA|asn|64500|2|20220101|assigned|opaque-record\n"
    b"ripencc|ZZ|asn|64502|1|20220101|allocated|opaque-record\n"
    b"apnic|*|asn|64503|1|20220101|reserved\n"
    b"apnic|AU|ipv4|192.0.2.0|256|20220101|allocated\n"
)


def test_rir_context_outputs_coarse_registration_counts_only():
    meta, rows = analyze((REPORT[:73], REPORT[73:149], REPORT[149:]))
    assert meta["source_sha256"] == sha256(REPORT).hexdigest()
    assert meta["asn_rows_available"] == meta["asn_rows_downloaded"] == 3
    assert meta["geographic_basis"] == "rir_registration"
    assert meta["source_registration_country_codes"] == 1
    assert {row["registration_country_code"] for row in rows} == {"CA", None}
    assert sum(row["as_numbers_in_reported_ranges"] for row in rows) == 3
    assert "192.0.2.0" not in str(rows) and "64500" not in str(rows)


def test_rir_context_refuses_incomplete_input():
    with pytest.raises(DataError, match="row totals"):
        analyze([REPORT[: REPORT.rfind(b"apnic|AU")]])


def test_rir_context_accepts_last_line_without_trailing_newline():
    payload = REPORT.rstrip(b"\n")
    meta, _ = analyze([payload])
    assert meta["source_sha256"] == sha256(payload).hexdigest()
    assert meta["source_records_downloaded"] == 4


def test_wdi_context_keeps_missing_and_measured_zero_distinct():
    economies = [
        {
            "id": "CAN",
            "iso2Code": "CA",
            "name": "Canada",
            "region": {"id": "NAC", "value": "North America"},
        },
        {
            "id": "WLD",
            "iso2Code": "1W",
            "name": "World",
            "region": {"id": "NA", "value": "Aggregates"},
        },
    ]
    metrics = [
        {"indicator": {"id": INDICATOR}, "countryiso3code": code, "date": year, "value": value}
        for code, year, value in (
            ("CAN", "2021", None),
            ("CAN", "2022", 0),
            ("CAN", "2023", 105.1),
            ("WLD", "2022", 75),
            ("OTHER", "2022", 11),
        )
    ]
    countries, rows, counts = project(economies, metrics)
    assert [row["alpha2"] for row in countries] == ["CA"]
    assert [row["subscriptions_per_100_people"] for row in rows] == [None, 0.0, 105.1]
    assert counts["source_measured_zero_rows"] == counts["country_rows_missing"] == 1
    assert counts["aggregate_rows_excluded"] == counts["unmatched_rows_excluded"] == 1
