"""Synthetic HTTP cases. These tests make no external requests."""

import json
from pathlib import Path

import httpx
import pytest

from pipelines import fetch


def test_retry_after_and_permanent_4xx(monkeypatch: pytest.MonkeyPatch) -> None:
    waits = []
    responses = iter([httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(403)])
    monkeypatch.setattr(fetch.time, "sleep", waits.append)
    with httpx.Client(transport=httpx.MockTransport(lambda _: next(responses))) as client:
        capture, content = fetch.request(client, "nvd", fetch.NVD)
    assert content is None
    assert waits == [7]
    assert capture.error_code == "http_403"
    assert [a.http_status for a in capture.attempts] == [429, 403]


def test_retry_budget_and_long_retry_after(monkeypatch: pytest.MonkeyPatch) -> None:
    waits = []
    monkeypatch.setattr(fetch.time, "sleep", waits.append)
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(503))) as client:
        capture, _ = fetch.request(client, "cisa", fetch.CISA)
    assert len(capture.attempts) == fetch.MAX_ATTEMPTS
    assert len(waits) == fetch.MAX_ATTEMPTS - 1

    def rate_limit(_: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "120"})

    with httpx.Client(transport=httpx.MockTransport(rate_limit)) as client:
        capture, _ = fetch.request(client, "cisa", fetch.CISA)
    assert len(capture.attempts) == 1
    assert capture.attempts[0].retry_after_seconds == 120


def test_shodan_discards_account_and_facet_data(tmp_path: Path) -> None:
    (tmp_path / "raw").mkdir()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api-info":
            return httpx.Response(200, json={"plan": "dev", "account": "unit-fixture"})
        assert request.url.path == "/shodan/host/count"
        assert request.url.params["query"] == "http"
        return httpx.Response(200, json={"facets": {"country": [{"value": "ZZ", "count": 3}]}})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        captures, status = fetch.check_shodan(client, tmp_path, "synthetic-secret")
    assert status == "generic_country_facet_only"
    assert all("synthetic-secret" not in outcome.model_dump_json() for outcome in captures)
    assert [json.loads(file.read_bytes()) for file in sorted((tmp_path / "raw").iterdir())] == [
        {"free_plan": True},
        {"country_facet": True},
    ]


def test_shodan_unconfirmed_plan_does_not_request_counts(tmp_path: Path) -> None:
    (tmp_path / "raw").mkdir()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api-info"
        return httpx.Response(200, json={"plan": "enterprise"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert fetch.check_shodan(client, tmp_path, None) == ([], "missing_optional_credentials")
        captures, status = fetch.check_shodan(client, tmp_path, "synthetic-secret")
    assert len(captures) == 1
    assert status == "free_plan_unconfirmed"
