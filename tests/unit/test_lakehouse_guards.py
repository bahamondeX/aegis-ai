"""Isolated unit inputs exercising authorization, Athena bounds and S3 integrity."""

import io
from datetime import UTC, date, datetime
from uuid import uuid4

import boto3
import pytest
from botocore.response import StreamingBody
from botocore.stub import Stubber

from infra.settings import Settings
from pipelines.athena import AthenaReader, render, value_for
from pipelines.cloud import Published, SnapshotStore
from pipelines.io import DataError, digest
from pipelines.query import Query
from schemas.tables import TABLES


def test_cloud_writer_needs_target_and_explicit_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    account = "123456789012"
    monkeypatch.setenv("AEGIS_AWS_ACCOUNT", account)
    monkeypatch.setenv("AEGIS_AWS_REGION", "us-east-1")
    monkeypatch.setenv("AEGIS_AWS_PROFILE", "unit-test")
    monkeypatch.setenv("AEGIS_PROJECT_PREFIX", "aegis-unit")
    monkeypatch.delenv("AEGIS_DEPLOY_APPROVAL", raising=False)
    settings = Settings.load()
    with pytest.raises(DataError, match="explicit AEGIS_DEPLOY_APPROVAL"):
        settings.authorize()
    monkeypatch.setenv("AEGIS_DEPLOY_APPROVAL", f"{account}/us-east-1/aegis-unit")
    monkeypatch.setenv("AEGIS_BUDGET_USD", "NaN")
    with pytest.raises(DataError, match="finite and positive"):
        settings.authorize()
    monkeypatch.setenv("AEGIS_BUDGET_USD", "5")
    assert settings.authorize() == 5


def test_athena_snapshot_literals_and_provider_result_values() -> None:
    release = Published(
        run_id=uuid4(), score_date=date(2026, 1, 1), snapshots=dict.fromkeys(TABLES, 19)
    )
    sql = render("aegis_unit", release, Query.GEO, limit=20, country_iso2="PE")
    assert 'FROM "aegis_unit"."fact_geo_exposure" FOR VERSION AS OF 19' in sql
    assert "country_iso2 = 'PE'" in sql
    assert "LIMIT 20" in sql
    with pytest.raises(DataError, match="country"):
        render("aegis_unit", release, Query.GEO, country_iso2="PE'--")
    with pytest.raises(DataError, match="threshold"):
        render("aegis_unit", release, Query.RANKING, min_epss=float("nan"))
    with pytest.raises(DataError, match="database"):
        render("elsewhere", release, Query.COVERAGE)
    assert value_for("retrieved_at", "timestamp with time zone", "2026-01-01 00:00:00.123 UTC") == (
        datetime(2026, 1, 1, microsecond=123000, tzinfo=UTC)
    )


def test_athena_polling_timeout_requests_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    client = boto3.Session().client(
        "athena", region_name="us-east-1", aws_access_key_id="stub", aws_secret_access_key="stub"
    )
    reader = AthenaReader(client, "aegis_unit", "aegis-unit")
    release = Published(
        run_id=uuid4(), score_date=date(2026, 1, 1), snapshots=dict.fromkeys(TABLES, 19)
    )
    times = iter((0, 46))
    monkeypatch.setattr("pipelines.athena.time.monotonic", lambda: next(times))
    with Stubber(client) as aws:
        aws.add_response(
            "start_query_execution",
            {"QueryExecutionId": "unit-query"},
            {
                "QueryString": render("aegis_unit", release, Query.COVERAGE),
                "QueryExecutionContext": {"Database": "aegis_unit"},
                "WorkGroup": "aegis-unit",
            },
        )
        aws.add_response("stop_query_execution", {}, {"QueryExecutionId": "unit-query"})
        with pytest.raises(DataError, match="polling budget"):
            reader.query(release, Query.COVERAGE)
        aws.assert_no_pending_responses()


def test_immutable_s3_write_accepts_same_bytes_only() -> None:
    client = boto3.Session().client(
        "s3", region_name="us-east-1", aws_access_key_id="stub", aws_secret_access_key="stub"
    )
    store = SnapshotStore(client, "aegis-unit")
    key = "snapshots/unit/capture.json"
    body = b"synthetic unit fixture"
    with Stubber(client) as aws:
        for existing in (body, b"changed"):
            aws.add_client_error(
                "put_object",
                service_error_code="PreconditionFailed",
                http_status_code=412,
                expected_params={
                    "Bucket": store.bucket,
                    "Key": key,
                    "Body": body,
                    "IfNoneMatch": "*",
                    "Metadata": {"sha256": digest(body)},
                },
            )
            aws.add_response(
                "get_object",
                {
                    "Body": StreamingBody(io.BytesIO(existing), len(existing)),
                    "ContentLength": len(existing),
                    "Metadata": {"sha256": digest(existing)},
                },
                {"Bucket": store.bucket, "Key": key},
            )
        store.put(key, body)
        with pytest.raises(DataError, match="immutable"):
            store.put(key, body)
        aws.assert_no_pending_responses()
