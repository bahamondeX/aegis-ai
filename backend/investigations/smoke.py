"""Verify live SSE with the real G3 snapshot and official MCP transports."""

import asyncio
import json
from time import monotonic
from uuid import UUID, uuid4

import httpx
from fastapi import FastAPI

from backend.auth import mint
from backend.investigations.contracts import (
    AnalyticsEvent,
    EvidenceEvent,
    ProposalEvent,
    ReportEvent,
)
from backend.investigations.routes import ADAPTER
from backend.smoke import live_server


async def run(
    base: str, key: str, snapshot: UUID, *, require_bedrock: bool = False, runtime: bool = False
) -> None:
    headers = {"Authorization": f"Bearer {mint(key)}", "Idempotency-Key": uuid4().hex}
    path = "/invocations" if runtime else "/v1/investigations"
    async with httpx.AsyncClient(base_url=base, timeout=55, trust_env=False) as client:
        if runtime:
            ping = await client.get("/ping")
            assert ping.status_code == 200 and ping.json() == {"status": "Healthy"}
        request = {
            "question": "Prioritize known exploited vulnerabilities",
            "snapshot_id": str(snapshot),
        }
        assert (await client.post(path, json=request)).status_code == 401
        foreign = {**headers, "Authorization": f"Bearer {mint(key, workspace='foreign')}"}
        assert (await client.post(path, json=request, headers=foreign)).status_code == 403
        started = monotonic()
        first_byte_ms: float | None = None
        events = []
        async with client.stream("POST", path, json=request, headers=headers) as response:
            response.raise_for_status()
            assert response.headers["content-type"].startswith("text/event-stream")
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    if first_byte_ms is None:
                        first_byte_ms = (monotonic() - started) * 1_000
                    events.append(ADAPTER.validate_json(line.removeprefix("data: ")))
        elapsed_ms = (monotonic() - started) * 1_000
        assert first_byte_ms is not None and first_byte_ms < elapsed_ms
        assert events[0].type == "investigation.started" and events[-1].type == "done"
        assert [item.seq for item in events] == list(range(1, len(events) + 1))
        assert sum(item.type == "done" for item in events) == 1
        known = {
            entry.evidence_id
            for item in events
            if isinstance(item, EvidenceEvent)
            for entry in item.payload.items
        }
        report = next(item.payload for item in events if isinstance(item, ReportEvent))
        proposal = next(item.payload for item in events if isinstance(item, ProposalEvent))
        assert proposal.snapshot_id == snapshot and proposal.command == "propose_filters"
        assert report.snapshot_id == snapshot and report.claims
        assert all(
            set(claim.evidence_ids) <= known and claim.evidence_ids for claim in report.claims
        )
        assert report.analysis_mode == ("bedrock" if require_bedrock else "deterministic")
        if require_bedrock:
            assert report.usage
        replay = await client.post(path, json=request, headers={**headers, "Last-Event-ID": "1"})
        replay.raise_for_status()
        seen = [
            ADAPTER.validate_json(line[6:])
            for line in replay.text.splitlines()
            if line.startswith("data: ")
        ]
        assert seen == events[1:]
        identifier = events[0].investigation_id
        if runtime:
            cancel = {"action": "cancel", "investigation_id": str(identifier)}
            assert (await client.post(path, json=cancel, headers=foreign)).status_code == 403
            assert (await client.post(path, json=cancel, headers=headers)).json()[
                "status"
            ] == "completed"
        else:
            cancel_path = f"{path}/{identifier}/cancel"
            assert (await client.post(cancel_path, headers=foreign)).status_code == 403
            assert (await client.post(cancel_path, headers=headers)).json()["status"] == "completed"
        conflicting = await client.post(
            path, json={**request, "question": "Another scope"}, headers=headers
        )
        assert conflicting.status_code == 409
        regional = await client.post(
            path,
            headers={**headers, "Idempotency-Key": uuid4().hex},
            json={"question": "What evidence is available for South America?"},
        )
        regional.raise_for_status()
        scoped = [
            ADAPTER.validate_json(line[6:])
            for line in regional.text.splitlines()
            if line.startswith("data: ")
        ]
        regional_report = next(item.payload for item in scoped if isinstance(item, ReportEvent))
        assert regional_report.scope == "unsupported_region" and not regional_report.claims
        assert not regional_report.usage and scoped[-1].type == "done"
        assert not any(item.type == "ui.filters.proposed" for item in scoped)
        country = await client.post(
            path,
            headers={**headers, "Idempotency-Key": uuid4().hex},
            json={"question": "Any verified exposure?", "filters": {"country_iso2": "PE"}},
        )
        country.raise_for_status()
        country_events = [
            ADAPTER.validate_json(line[6:])
            for line in country.text.splitlines()
            if line.startswith("data: ")
        ]
        country_report = next(
            item.payload for item in country_events if isinstance(item, ReportEvent)
        )
        country_analytics = next(
            item.payload for item in country_events if isinstance(item, AnalyticsEvent)
        )
        assert country_report.scope == "country" and not country_report.claims
        assert country_analytics.geography == "unavailable" and country_analytics.risk is None
        assert not country_analytics.observations and not country_analytics.ranked_cve_ids
        print(
            json.dumps(
                {
                    "event": "g4.smoke",
                    "snapshot": str(snapshot),
                    "analysis_mode": report.analysis_mode,
                    "sse_events": len(events),
                    "claims": len(report.claims),
                    "evidence_ids": len(known),
                    "first_event_ms": round(first_byte_ms, 2),
                    "completed_ms": round(elapsed_ms, 2),
                    "regional_claims": len(regional_report.claims),
                    "country_observations": len(country_analytics.observations),
                    "usage": [entry.model_dump() for entry in report.usage],
                    "runtime": runtime,
                }
            ),
            flush=True,
        )


def smoke(
    app: FastAPI, key: str, snapshot: UUID, *, require_bedrock: bool = False, runtime: bool = False
) -> None:
    with live_server(app) as base:
        asyncio.run(run(base, key, snapshot, require_bedrock=require_bedrock, runtime=runtime))
