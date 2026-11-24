"""Isolated authentication and renderer checks with synthetic unit inputs."""

from datetime import date
from typing import Any
from uuid import uuid4

import pytest

from backend.auth import LOCAL_AUDIENCE, LOCAL_ISSUER, Auth, mint
from backend.models import Filters, ServiceError, Vulnerability
from backend.reader import SnapshotReader, View
from pipelines.cloud import Published
from schemas.tables import TABLES


def test_loopback_token_cannot_authenticate_from_remote_peer() -> None:
    key = "synthetic-unit-key-with-no-production-destination"
    auth = Auth(issuer=LOCAL_ISSUER, audience=LOCAL_AUDIENCE, workspace="local", local_key=key)
    bearer = f"Bearer {mint(key)}"
    assert auth.authenticate(bearer, "127.0.0.1") == "local-operator"
    with pytest.raises(ServiceError) as rejected:
        auth.authenticate(bearer, "192.0.2.1")
    assert rejected.value.status == 403


def test_athena_adapter_renders_only_pinned_tables_and_validated_values() -> None:
    release = Published(
        run_id=uuid4(), score_date=date(2026, 1, 1), snapshots=dict.fromkeys(TABLES, 23)
    )

    class CapturingReader:
        database = "aegis_unit"

        def _select(
            self, sql: str, *, max_rows: int
        ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
            assert 'FROM "aegis_unit"."dim_cve" FOR VERSION AS OF 23' in sql
            assert '"fact_epss" FOR VERSION AS OF 23' in sql
            assert "WHERE score_date=DATE '2026-01-01'" in sql
            assert "c.cve_id IN ('CVE-2026-1234')" in sql
            assert "c.kev_added_at >= DATE '2026-01-01'" in sql
            assert "JSON_FORMAT(CAST(source_refs AS JSON))" in sql
            assert " LIMIT 2" in sql and "?" not in sql
            assert max_rows == 2
            return [], {}

    reader = SnapshotReader.cloud(CapturingReader(), release, geo_available=False)
    filters = Filters(cve_ids=("CVE-2026-1234",), date_from=date(2026, 1, 1), limit=2)
    assert reader.view_rows(View.CVES, filters, Vulnerability) == []


def test_cognito_access_tokens_require_client_expiry_and_workspace(monkeypatch) -> None:
    from datetime import UTC, datetime, timedelta
    from types import SimpleNamespace

    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    from backend.models import ServiceError

    issuer = "https://cognito-idp.example.invalid/synthetic"
    auth = Auth(
        issuer=issuer,
        audience="synthetic-browser",
        workspace="project",
        jwks_url=f"{issuer}/jwks.json",
        cognito=True,
    )
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert auth.jwks
    monkeypatch.setattr(
        auth.jwks, "get_signing_key_from_jwt", lambda _: SimpleNamespace(key=private.public_key())
    )
    now = datetime.now(UTC)
    base = {
        "sub": "test-operator",
        "iss": issuer,
        "exp": now + timedelta(minutes=5),
        "client_id": "synthetic-browser",
        "token_use": "access",
        "cognito:groups": ["project"],
    }

    def authenticate(patch: dict) -> str:
        token = jwt.encode({**base, **patch}, private, algorithm="RS256")
        return auth.authenticate(f"Bearer {token}", "192.0.2.42")

    assert authenticate({}) == "test-operator"
    for patch, status in [
        ({"token_use": "id"}, 401),
        ({"client_id": "foreign-client"}, 401),
        ({"iss": "https://other.example.invalid/"}, 401),
        ({"exp": now - timedelta(seconds=10)}, 401),
        ({"cognito:groups": ["foreign"]}, 403),
        ({"cognito:groups": "project"}, 403),
    ]:
        with pytest.raises(ServiceError) as error:
            authenticate(patch)
        assert error.value.status == status


def test_cisa_guidance_query_is_pinned_and_bound_in_athena() -> None:
    from backend.cve_detail import guidance

    release = Published(
        run_id=uuid4(), score_date=date(2026, 1, 1), snapshots=dict.fromkeys(TABLES, 42)
    )

    class CapturingReader:
        database = "aegis_unit"

        def _select(self, sql: str, *, max_rows: int):
            assert 'FROM "aegis_unit"."evidence" FOR VERSION AS OF 42' in sql
            assert f"evidence_id='{('a' * 64)}'" in sql
            assert "source='cisa' AND source_record_id='CVE-2026-1234' LIMIT 1" in sql
            assert max_rows == 1 and "?" not in sql
            return [], {}

    reader = SnapshotReader.cloud(
        CapturingReader(), release, geo_available=False, cisa_archive=lambda: b""
    )
    assert guidance(reader, "CVE-2026-1234", "a" * 64) is None
