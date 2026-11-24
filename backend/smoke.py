"""Exercise both HTTP transports against the pinned, real DuckDB snapshot."""

import asyncio
import json
import socket
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Thread
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from backend.auth import mint
from backend.reader import SnapshotReader
from pipelines.io import selected_snapshot
from pipelines.query import Query, connect, query

TOOLS = {
    "get_vulnerabilities",
    "get_risk_summary",
    "get_exposure_by_country",
    "get_relationship_graph",
    "get_evidence",
    "propose_ui_filters",
}


async def check(base: str, key: str, reader: SnapshotReader, root: Path) -> None:
    async with httpx.AsyncClient(base_url=base, timeout=10, trust_env=False) as client:
        healthy = await client.get("/health")
        assert healthy.json() == {"status": "ok", "snapshot_id": str(reader.snapshot)}
        assert (await client.get("/v1/cves")).status_code == 401
        assert (await client.post("/mcp/")).status_code == 401
        for token, status in (
            (mint(key, expires=-1), 401),
            (mint(key, audience="other-api"), 401),
            (mint(key, workspace="foreign"), 403),
        ):
            headers = {"Authorization": f"Bearer {token}"}
            assert (await client.get("/v1/cves", headers=headers)).status_code == status
            assert (await client.post("/mcp/", headers=headers)).status_code == status

        client.headers["Authorization"] = f"Bearer {mint(key)}"
        coverage = (await client.get("/v1/coverage")).raise_for_status().json()["data"]
        assert {row["source"] for row in coverage} == {"cisa", "epss", "nvd", "shodan"}
        assert all(row["source_date"] for row in coverage if row["source"] in {"cisa", "epss"})
        for params in (
            {"limit": 201},
            {"min_epss": "-1"},
            {"country_iso2": "PER"},
            {"x": "unknown"},
            {"cve_ids": "CVE-2024-1234-INVALID"},
            {"date_from": "2025-01-01", "date_to": "2024-01-01"},
        ):
            invalid = await client.get("/v1/cves", params=params)
            assert (
                invalid.status_code == 422 and invalid.json()["error"]["code"] == "invalid_filters"
            )
        kpis = (await client.get("/v1/kpis")).raise_for_status().json()["data"]
        with connect(selected_snapshot(root, reader.snapshot) / "aegis.duckdb") as db:
            expected = query(db, Query.RANKING, limit=4)
            assert kpis["total_cves"] == db.execute("SELECT COUNT(*) FROM dim_cve").fetchone()[0]
        first = (
            (await client.get("/v1/cves", params={"limit": 4})).raise_for_status().json()["data"]
        )
        assert [c["cve_id"] for c in first] == [c["cve_id"] for c in expected]
        assert first == (await client.get("/v1/cves", params={"limit": 4})).json()["data"]
        cve = first[0]["cve_id"]
        evidence_id = first[0]["source_refs"][0]
        linked = (await client.get(f"/v1/evidence/{evidence_id}")).raise_for_status().json()["data"]
        assert linked["source_record_id"] == cve and linked["uri"].startswith("https://")
        missing = await client.get(f"/v1/evidence/{'0' * 64}")
        assert missing.status_code == 404
        graph = (await client.get("/v1/graph", params={"cve_ids": cve})).raise_for_status().json()
        assert graph["data"] and all(e["cve_id"] == cve for e in graph["data"])

        map_read = (await client.get("/v1/map", params={"country_iso2": "PE"})).raise_for_status()
        if not reader.geo_available:
            assert (
                map_read.json()["data"] == [] and map_read.json()["availability"] == "unavailable"
            )
            regional = await client.get("/v1/cves", params={"country_iso2": "PE"})
            assert (
                regional.json()["data"] == [] and regional.json()["availability"] == "unavailable"
            )

        async with streamable_http_client(f"{base}/mcp/", http_client=client) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                catalog = await session.list_tools()
                assert {t.name for t in catalog.tools} == TOOLS
                assert all(t.inputSchema and t.outputSchema for t in catalog.tools)
                checks: list[tuple[str, dict[str, Any]]] = [
                    ("get_vulnerabilities", {"filters": {"cve_ids": [cve], "limit": 1}}),
                    ("get_risk_summary", {}),
                    ("get_exposure_by_country", {"filters": {"country_iso2": "PE"}}),
                    ("get_relationship_graph", {"filters": {"cve_ids": [cve]}}),
                    ("get_evidence", {"evidence_id": evidence_id}),
                    ("propose_ui_filters", {"filters": {"cve_ids": [cve], "min_epss": 0.5}}),
                ]
                responses = {}
                for tool, args in checks:
                    result = await session.call_tool(tool, args)
                    assert not result.isError and result.structuredContent
                    payload = result.structuredContent
                    assert payload["snapshot_id"] == str(reader.snapshot) and payload["coverage"]
                    responses[tool] = payload
                assert responses["get_vulnerabilities"]["data"] == [first[0]]
                assert responses["get_risk_summary"]["data"] == kpis
                assert responses["get_evidence"]["data"] == linked
                assert responses["get_relationship_graph"]["data"] == graph["data"]
                assert responses["get_exposure_by_country"]["data"] == map_read.json()["data"]
                assert responses["propose_ui_filters"]["data"]["cve_ids"] == [cve]
                wrong = await session.call_tool("get_evidence", {"evidence_id": "0" * 64})
                assert wrong.isError and any(
                    "not_found" in getattr(c, "text", "") for c in wrong.content
                )
        print(
            json.dumps(
                {
                    "event": "g3.smoke",
                    "snapshot": str(reader.snapshot),
                    "http_routes_checked": 7,
                    "mcp_tools_called": len(checks),
                    "total_cves": kpis["total_cves"],
                    "geo_availability": map_read.json()["availability"],
                    "authenticated_transport": "streamable-http",
                }
            ),
            flush=True,
        )


@contextmanager
def live_server(app: FastAPI) -> Iterator[str]:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, log_level="warning", proxy_headers=False))
        thread = Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.05)
            if not server.started:
                raise RuntimeError("local API did not start within ten seconds")
            yield f"http://127.0.0.1:{port}"
        finally:
            server.should_exit = True
            thread.join(5)
        if thread.is_alive():
            raise RuntimeError("local API failed to stop")


def verify(app: FastAPI, key: str, reader: SnapshotReader, root: Path) -> None:
    with live_server(app) as url:
        asyncio.run(check(url, key, reader, root))
