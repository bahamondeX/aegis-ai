"""Authenticated REST and AgentCore HTTP entrypoints for a single served snapshot."""

import asyncio
import re
from uuid import UUID

from fastapi import APIRouter, FastAPI
from fastapi import Request as HttpRequest
from fastapi.responses import StreamingResponse
from pydantic import TypeAdapter

from backend.auth import Auth
from backend.investigations.contracts import CancelRequest, Event, Request
from backend.investigations.service import InvestigationService, owner_key
from backend.models import ServiceError

ADAPTER = TypeAdapter(Event)


def install(app: FastAPI, auth: Auth, service: InvestigationService, *, runtime: bool) -> None:
    routes = APIRouter()

    async def subject(request: HttpRequest) -> tuple[str, str, str]:
        authorization = request.headers.get("Authorization", "")
        peer = request.client.host if request.client else ""
        user = await asyncio.to_thread(auth.authenticate, authorization, peer)
        return user, authorization, peer

    async def investigate(request: HttpRequest, payload: Request) -> StreamingResponse:
        user, authorization, peer = await subject(request)
        key = request.headers.get("Idempotency-Key", "")
        if not re.fullmatch(r"[A-Za-z0-9._-]{16,128}", key):
            raise ServiceError(
                "invalid_key", "Idempotency-Key must be 16 to 128 safe characters", 422
            )
        cursor = request.headers.get("Last-Event-ID", "0")
        if not re.fullmatch(r"[0-9]{1,3}", cursor):
            raise ServiceError("invalid_cursor", "Last-Event-ID must be an event sequence", 422)
        after = int(cursor)
        record, new = await asyncio.to_thread(
            service.start, auth.workspace, user, key, payload, after
        )
        task = (
            asyncio.create_task(service.run(record, payload, user, app, authorization, peer))
            if new
            else None
        )

        async def still_authorized() -> bool:
            try:
                await asyncio.to_thread(auth.authenticate, authorization, peer)
            except ServiceError:
                return False
            return True

        return StreamingResponse(
            service.stream(
                record, after, task, access_check=still_authorized if auth.directory else None
            ),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    async def cancel(request: HttpRequest, investigation_id: UUID) -> dict[str, str]:
        user, _, _ = await subject(request)
        record = await service.cancel(investigation_id, owner_key(auth.workspace, user))
        return {"investigation_id": str(record.id), "status": record.status}

    @routes.get("/v1/investigation-events/schema")
    async def schema(request: HttpRequest) -> dict:
        await subject(request)
        return ADAPTER.json_schema(mode="serialization")

    if runtime:

        @routes.post("/invocations", response_model=None)
        async def invoke(
            request: HttpRequest, payload: Request | CancelRequest
        ) -> StreamingResponse | dict[str, str]:
            if isinstance(payload, CancelRequest):
                return await cancel(request, payload.investigation_id)
            return await investigate(request, payload)

        @routes.get("/ping")
        async def runtime_ping() -> dict[str, str]:
            return {"status": "Healthy"}

    else:
        routes.post(
            "/v1/investigations",
            response_class=StreamingResponse,
            responses={200: {"content": {"text/event-stream": {}}}},
        )(investigate)
        routes.post("/v1/investigations/{investigation_id}/cancel")(cancel)

    app.include_router(routes)
