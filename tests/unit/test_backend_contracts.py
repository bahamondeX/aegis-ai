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
