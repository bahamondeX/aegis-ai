"""Local and botocore contract checks for V2 publication and resume."""

import gzip
import io
import json
from datetime import date
from pathlib import Path

import boto3
import httpx
import pytest
from botocore.response import StreamingBody
from botocore.stub import ANY, Stubber

from infra.settings import Settings
from pipelines.bronze import PREFIX, LocalBronze, S3Bronze, artifact, ensure, put_record, record
from pipelines.bronze_migrate import Item, authorized_store, describe, migrate
from pipelines.bulk_epss import git_blob_sha1
from pipelines.epss_bronze import (
    campaign_key,
    check_dispatch,
    dispatch_key,
    plan_id,
    run_date,
    stage_plan,
)
from pipelines.io import DataError


def test_local_migration_resume_reuses_data_and_checks_committed_objects(tmp_path):
    root = tmp_path / "store"
    store = LocalBronze(root)
    payload = tmp_path / "payload"
    payload.write_bytes(b"test article")
    ref = artifact("kev", "raw", payload)
    item = Item("local/payload", ref, payload)
    plan = describe([item, Item("alias/payload", ref, payload)])
    assert plan["objects"] == 1
    assert migrate(store, [item], plan, 1)["uploaded"] == 1
    assert migrate(store, [item], plan, 1)["reused_manifest"] is True
    store.path(ref.key).write_bytes(b"changed bytes")
    with pytest.raises(DataError, match="failed verification"):
        migrate(store, [item], plan, 1)
    assert payload.read_bytes() == b"test article"


def test_s3_migration_requires_new_scope_before_creating_session(monkeypatch):
    def untouched(*_):
        pytest.fail("AWS session opened before V2 scope approval")

    monkeypatch.setattr(Settings, "identity", untouched)
    env = {
        "AEGIS_AWS_ACCOUNT": "111122223333",
        "AEGIS_AWS_REGION": "us-east-1",
        "AEGIS_AWS_PROFILE": "test",
        "AEGIS_DEPLOY_APPROVAL": "111122223333/us-east-1/aegis-dev",
        "AEGIS_BUDGET_USD": "15",
    }
    with pytest.raises(DataError, match="V2 migration"):
        authorized_store(env, {"id": "a" * 64, "bytes": 1, "objects": 1})


def test_s3_put_and_read_require_version_encryption_and_server_checksum(tmp_path):
    client = boto3.client(
        "s3", region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test"
    )
    owner = "111122223333"
    kms = f"arn:aws:kms:us-east-1:{owner}:key/test"
    store = S3Bronze(client, "example-lake", owner, kms)
    payload = tmp_path / "data"
    raw = b'{"value":1}'
    payload.write_bytes(raw)
    ref = artifact("epss", "manifests", payload)
    params = {"Bucket": "example-lake", "Key": ref.key, "ExpectedBucketOwner": owner}
    response = {
        "ContentLength": len(raw),
        "ChecksumSHA256": ref.checksum,
        "ChecksumType": "FULL_OBJECT",
        "VersionId": "version",
        "ServerSideEncryption": "aws:kms",
        "SSEKMSKeyId": kms,
    }
    with Stubber(client) as stub:
        stub.add_client_error(
            "head_object",
            service_error_code="403",
            http_status_code=403,
            expected_params={**params, "ChecksumMode": "ENABLED"},
        )
        stub.add_response(
            "list_objects_v2",
            {"IsTruncated": False, "KeyCount": 0},
            {
                "Bucket": "example-lake",
                "ExpectedBucketOwner": owner,
                "Prefix": ref.key,
                "MaxKeys": 1,
            },
        )
        stub.add_response(
            "put_object",
            {"VersionId": "version"},
            {
                **params,
                "Body": ANY,
                "ContentLength": len(raw),
                "ChecksumSHA256": ref.checksum,
                "IfNoneMatch": "*",
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": kms,
                "BucketKeyEnabled": True,
            },
        )
        stub.add_response("head_object", response, {**params, "ChecksumMode": "ENABLED"})
        observed, wrote = ensure(store, ref, payload)
        assert observed.version_id == "version" and wrote
        stub.add_response(
            "get_object",
            {**response, "Body": StreamingBody(io.BytesIO(raw), len(raw))},
            {**params, "ChecksumMode": "ENABLED"},
        )
        assert record(store, ref.key) == {"value": 1}
        stub.assert_no_pending_responses()


def test_ep_client_persists_attempt_and_skips_committed_date(tmp_path: Path):
    test_day = date(2021, 4, 14)
    payload = tmp_path / "source"
    raw = gzip.compress(b"cve,epss\nCVE-2020-2000,0.25\n")
    payload.write_bytes(raw)
    tree = tmp_path / "tree.json"
    tree.write_text(
        json.dumps(
            {
                "truncated": False,
                "sha": "a" * 40,
                "tree": [
                    {
                        "path": "2021/epss_scores-2021-04-14.csv.gz",
                        "type": "blob",
                        "size": len(raw),
                        "sha": git_blob_sha1(payload),
                    }
                ],
            }
        )
    )
    store = LocalBronze(tmp_path / "store")
    plan, _ = stage_plan(store, tree, test_day, test_day)
    responses = iter([b"invalid", raw])
    calls = 0

    def download(_):
        nonlocal calls
        calls += 1
        return httpx.Response(200, content=next(responses))

    with httpx.Client(transport=httpx.MockTransport(download)) as client:
        with pytest.raises(DataError):
            run_date(store, client, plan, test_day, 1)
        failed = f"{PREFIX}/manifests/epss-jobs/{plan}/{test_day}/1/outcome.json"
        assert record(store, failed)["state"] == "failed"
        assert run_date(store, client, plan, test_day, 1)["state"] == "reserved"
        result = run_date(store, client, plan, test_day, 2)
        assert result["counts"]["valid"] == 1
        assert result["counts"]["missing_percentile"] == 1
        assert run_date(store, client, plan, test_day, 2)["reused"] is True
        assert calls == 2


def test_campaign_requires_pinned_window_date_and_immutable_dispatch(tmp_path: Path):
    store = LocalBronze(tmp_path)
    window, day = "a" * 64, "2021-04-14"
    value = {"windows": {window: {day: 512 * 1024}}}
    campaign = plan_id(value)
    put_record(store, campaign_key(campaign), value)
    event = {"campaign": campaign, "plan": window, "date": day, "attempt": 1}
    with pytest.raises(DataError, match="no reserved dispatch"):
        check_dispatch(store, event, campaign)
    put_record(store, dispatch_key(campaign, window, day, 1), event)
    assert check_dispatch(store, event, campaign) == 512 * 1024
    with pytest.raises(DataError, match="outside the reviewed historical dispatch"):
        check_dispatch(store, {**event, "date": "2021-04-15"}, campaign)
    with pytest.raises(DataError, match="outside its reviewed historical campaign"):
        check_dispatch(store, {**event, "plan": "b" * 64}, campaign)
