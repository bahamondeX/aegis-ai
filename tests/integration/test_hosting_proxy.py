"""Loopback proof of the standalone API relay using real data and the runtime entrypoint."""

import asyncio
import os
import secrets
from pathlib import Path
from time import monotonic
from uuid import UUID, uuid4

import httpx
import pytest

from backend.api import create_app
from backend.auth import LOCAL_AUDIENCE, LOCAL_ISSUER, Auth, mint
from backend.cloud_api import gateway
from backend.investigations.routes import ADAPTER
from backend.investigations.service import InvestigationService
from backend.investigations.store import SQLiteStore
from backend.reader import SnapshotReader
from backend.smoke import live_server

pytestmark = pytest.mark.live


def test_hosted_path_relays_authenticated_stream_without_buffering(tmp_path: Path) -> None:
    reader = SnapshotReader.duckdb(
        Path(os.environ["AEGIS_DATA_DIR"]), UUID(os.environ["AEGIS_SNAPSHOT"])
    )
    key = secrets.token_urlsafe(48)
    auth = Auth(issuer=LOCAL_ISSUER, audience=LOCAL_AUDIENCE, workspace="local", local_key=key)
    graph = InvestigationService(SQLiteStore(tmp_path / "runtime.db"), reader.snapshot)

    async def verify(api: str) -> None:
        async with httpx.AsyncClient(base_url=api, timeout=12, trust_env=False) as client:
            start = "/api/aegis/v1/investigations"
            body = {
                "question": "Prioritize known exploited vulnerabilities",
                "snapshot_id": str(reader.snapshot),
            }
            headers = {"Authorization": f"Bearer {mint(key)}", "Idempotency-Key": uuid4().hex}
            other = {**headers, "Authorization": f"Bearer {mint(key, workspace='foreign')}"}
            assert (await client.get("/api/aegis/v1/map")).status_code == 401
            assert (await client.get("/api/aegis/openapi.json", headers=headers)).status_code == 404
            assert (await client.post(start, json=body, headers=other)).status_code == 403
            assert (
                await client.post(
                    start, json={**body, "snapshot_id": str(uuid4())}, headers=headers
                )
            ).status_code == 409

            sent_at = monotonic()
            events = []
            observed_first = None
            async with client.stream("POST", start, json=body, headers=headers) as response:
                assert (
                    response.status_code == 200 and response.headers["cache-control"] == "no-store"
                )
                async for line in response.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    event = ADAPTER.validate_json(line[6:])
                    events.append(event)
                    if observed_first is None:
                        observed_first = monotonic()
                        assert event.type == "investigation.started"
            assert observed_first is not None and observed_first < monotonic()
            assert events[-1].type == "done" and events[-1].payload.status == "completed"

            second = {**headers, "Idempotency-Key": uuid4().hex}
            async with client.stream("POST", start, json=body, headers=second) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    event = ADAPTER.validate_json(line[6:])
                    if event.type == "investigation.started":
                        result = await client.post(
                            f"{start}/{event.investigation_id}/cancel", headers=second
                        )
                        assert result.status_code == 200 and result.json()["status"] == "cancelled"
                    if event.type == "done":
                        assert event.payload.status == "cancelled"
            replay = await client.post(start, json=body, headers={**headers, "Last-Event-ID": "1"})
            replay.raise_for_status()
            assert [
                ADAPTER.validate_json(line[6:])
                for line in replay.text.splitlines()
                if line.startswith("data: ")
            ] == events[1:]
            print("hosted path loopback first SSE ms", round((observed_first - sent_at) * 1000, 2))

    with live_server(create_app(reader, auth, graph, runtime=True)) as upstream:
        relay = httpx.AsyncClient(timeout=12, trust_env=False)
        with live_server(gateway(reader, auth, upstream + "/invocations", relay)) as api:
            asyncio.run(verify(api))
