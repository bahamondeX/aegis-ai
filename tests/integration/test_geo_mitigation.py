"""Real snapshot authentication, release binding and public-safe geography."""

import os
import secrets
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest

from backend.api import create_app
from backend.auth import LOCAL_AUDIENCE, LOCAL_ISSUER, Auth, mint
from backend.investigations.routes import ADAPTER
from backend.investigations.service import InvestigationService
from backend.investigations.store import SQLiteStore
from backend.models import Filters
from backend.reader import SnapshotReader
from backend.smoke import live_server

pytestmark = pytest.mark.live


def test_qualified_projection_and_cve_detail_fail_closed(tmp_path: Path) -> None:
    reader = SnapshotReader.duckdb(
        Path(os.environ["AEGIS_DATA_DIR"]), UUID(os.environ["AEGIS_SNAPSHOT"])
    )
    row = reader.vulnerabilities(Filters(limit=1)).data[0]
    key = secrets.token_urlsafe(48)
    auth = Auth(issuer=LOCAL_ISSUER, audience=LOCAL_AUDIENCE, workspace="local", local_key=key)
    investigations = InvestigationService(SQLiteStore(tmp_path / "runs.db"), reader.snapshot)
    app = create_app(reader, auth, investigations)

    with live_server(app) as base, httpx.Client(base_url=base, timeout=15) as client:
        path = f"/v1/cves/{row.cve_id}"
        valid = {"Authorization": f"Bearer {mint(key)}"}
        params = {"snapshot_id": str(reader.snapshot), "country_iso2": "PE"}

        for token, status in [
            (None, 401),
            (mint(key, expires=-30), 401),
            (mint(key, workspace="foreign"), 403),
        ]:
            headers = {} if token is None else {"Authorization": f"Bearer {token}"}
            assert client.get(path, params=params, headers=headers).status_code == status
            assert client.get("/v1/map", headers=headers).status_code == status
        assert (
            client.get(path, params={**params, "snapshot_id": uuid4()}, headers=valid).status_code
            == 409
        )

        response = client.get(path, params=params, headers=valid)
        response.raise_for_status()
        selected = response.json()
        assert selected["snapshot_id"] == params["snapshot_id"]
        assert selected["vulnerability"]["cve_id"] == row.cve_id
        assert selected["geography"]["country_iso2"] == "PE"
        assert selected["geography"]["count"] is None and not selected["observations"]
        assert selected["mitigation"]["source"] == "cisa"
        assert selected["mitigation"]["evidence_id"] in {
            item["evidence_id"] for item in selected["evidence"]
        }
        assert "raw_snapshot" not in response.text and "raw_file" not in response.text

        world = client.get("/v1/map", headers=valid).json()
        same_cve = client.get("/v1/map", params={"cve_ids": row.cve_id}, headers=valid).json()
        peru = client.get("/v1/map", params={"country_iso2": "PE"}, headers=valid).json()
        assert world["network"] == same_cve["network"]
        assert peru["network"]["records"] == []
        for value in (world, same_cve, peru):
            assert value["data"] == [] and value["exposure"]["state"] == "unavailable"
            assert value["exposure"]["count"] is None
            assert set(value["exposure"]) == {
                "state",
                "category",
                "country_iso2",
                "reason",
                "count",
                "precision",
                "unit",
                "window_start",
                "window_end",
                "evidence_id",
            }

        refused = client.post(
            "/v1/investigations",
            headers={**valid, "Idempotency-Key": uuid4().hex},
            json={
                "question": "Review archived guidance",
                "snapshot_id": str(reader.snapshot),
                "filters": {"cve_ids": [row.cve_id], "country_iso2": "PE"},
                "mitigation": {"cve_id": row.cve_id, "evidence_ids": ["f" * 64]},
            },
        )
        refused.raise_for_status()
        events = [
            ADAPTER.validate_json(line[6:])
            for line in refused.text.splitlines()
            if line.startswith("data: ")
        ]
        assert events[-2].type == "error" and events[-2].payload.code == "invalid_evidence"
        assert events[-1].type == "done" and events[-1].payload.status == "failed"
