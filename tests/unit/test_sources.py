"""Synthetic schema fixtures scoped to unit tests."""

import gzip
import json
from datetime import UTC, date, datetime

import pytest

from pipelines.fetch import next_cohort
from pipelines.io import DataError
from pipelines.normalize import cpe_product
from pipelines.parse import parse_epss, parse_nvd
from schemas.sources import NvdMetrics


def epss_fixture(rows: str) -> bytes:
    return gzip.compress(
        ("#model_version:test,score_date:2026-01-02\ncve,epss,percentile\n" + rows).encode()
    )


def test_epss_dates_and_normalization() -> None:
    day, version, table = parse_epss(epss_fixture("cve-2026-9001,0,1\n"))
    assert (day, version) == (datetime(2026, 1, 2, tzinfo=UTC), "test")
    assert table.row(0) == ("CVE-2026-9001", 0.0, 1.0)


def test_epss_preserves_timestamp_from_header() -> None:
    payload = gzip.decompress(epss_fixture("CVE-2026-9001,0.5,1\n"))
    payload = payload.replace(b"2026-01-02", b"2026-01-02T12:34:56Z")
    assert parse_epss(gzip.compress(payload))[0] == datetime(2026, 1, 2, 12, 34, 56, tzinfo=UTC)


@pytest.mark.parametrize(
    "rows",
    [
        "CVE-2026-9001,1.1,0.5\n",
        "CVE-2026-9001,0.2,NaN\n",
        "CVE-2026-9001,,0.5\n",
        "CVE-2026-9001,0.2,0.5\ncve-2026-9001,0.3,0.6\n",
        "not-a-cve,0.2,0.5\n",
        "",
    ],
)
def test_epss_rejects_bad_rows(rows: str) -> None:
    with pytest.raises(DataError):
        parse_epss(epss_fixture(rows))


def test_cursor_is_stable_across_reranking_and_restarts_at_end() -> None:
    ids = [f"CVE-2026-{9001 + i}" for i in range(4)]
    dates = [date(2026, 2, i) for i in (1, 2, 2, 2)]
    scores = dict(zip(ids, [1, 0.5, 0.6, 0.6], strict=True))
    candidates = list(zip(ids, dates, strict=True))
    assert next_cohort(candidates, scores, [], 2) == ([ids[2], ids[3]], [])
    assert next_cohort(candidates, scores, ids[2:], 2) == ([ids[1], ids[0]], ids[2:])
    assert next_cohort(candidates, scores, ids, 1) == ([ids[2]], [])


def test_cvss_uses_preferred_published_metric_and_ignores_ssvc() -> None:
    def metric(kind: str, source: str, version: str, score: float) -> dict:
        return {
            "source": source,
            "type": kind,
            "cvssData": {"version": version, "baseScore": score, "vectorString": "unit-fixture"},
        }

    metrics = NvdMetrics.model_validate(
        {
            "ssvcV203": [{"source": "unit-fixture"}],
            "cvssMetricV31": [metric("Primary", "test", "3.1", 9.1)],
            "cvssMetricV40": [metric("Secondary", "a", "4.0", 9), metric("Primary", "b", "4.0", 0)],
        }
    )
    preferred = metrics.preferred()
    assert preferred is not None
    assert (preferred.cvssData.version, preferred.cvssData.baseScore, preferred.source) == (
        "4.0",
        0,
        "b",
    )
    assert NvdMetrics().preferred() is None


def test_nvd_boundary_rejects_incomplete_page_and_unrequested_cve() -> None:
    wrapper = {
        "timestamp": "2026-01-02T12:00:00.000",
        "version": "2.0",
        "startIndex": 0,
        "totalResults": 1,
        "resultsPerPage": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-9001",
                    "published": "2026-01-01T12:00:00.000",
                    "lastModified": "2026-01-01T12:00:00.000",
                    "descriptions": [],
                }
            }
        ],
    }
    _, records = parse_nvd(json.dumps(wrapper).encode(), ["CVE-2026-9001", "CVE-2026-9002"])
    assert list(records) == ["CVE-2026-9001"]
    with pytest.raises(DataError, match="out-of-cohort"):
        parse_nvd(json.dumps(wrapper).encode(), ["CVE-2026-9002"])
    wrapper["totalResults"] = 2
    with pytest.raises(DataError, match="incomplete"):
        parse_nvd(json.dumps(wrapper).encode(), ["CVE-2026-9001", "CVE-2026-9002"])


def test_cpe_preserves_escaped_component_separator() -> None:
    assert cpe_product(r"cpe:2.3:a:vendor:unit\:fixture:*:*:*:*:*:*:*:*") == (
        "vendor",
        "unit:fixture",
    )
    with pytest.raises(DataError, match="malformed"):
        cpe_product("cpe:2.3:a:vendor")
