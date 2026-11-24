"""Durable, idempotent investigations and cancellable SSE replay."""

import asyncio
import hashlib
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, Field
from starlette.types import ASGIApp

from backend.investigations.bedrock import Select
from backend.investigations.contracts import (
    AnalyticsEvent,
    Completed,
    DoneEvent,
    ErrorEvent,
    ErrorPayload,
    Event,
    ProposalEvent,
    ReportEvent,
    Request,
    RunStatus,
    Started,
    StartEvent,
)
from backend.investigations.graph import execute
from backend.investigations.research import connect_tools
from backend.investigations.store import Store
from backend.models import ServiceError

RUN_SECONDS = 45
MAX_EVENTS = 32
HEARTBEAT_SECONDS = 2.0
LOGGER = logging.getLogger(__name__)


def identity_key(workspace: str, subject: str, key: str) -> UUID:
    value = "\0".join((workspace, subject, key)).encode()
    return UUID(bytes=hashlib.sha256(value).digest()[:16], version=4)


def owner_key(workspace: str, subject: str) -> str:
    return hashlib.sha256(f"{workspace}\0{subject}".encode()).hexdigest()


class Record(BaseModel):
    id: UUID
    owner: str
    digest: str
    snapshot: UUID
    trace: UUID
    expires: AwareDatetime
    status: RunStatus | Literal["running"] = "running"
    events: list[Event] = Field(default_factory=list)
    checkpoint: dict[str, Any] = Field(default_factory=dict)

    def append(self, model: type, payload: BaseModel) -> None:
        if len(self.events) >= MAX_EVENTS:
            raise ServiceError("event_budget", "investigation event budget exceeded", 503)
        self.events.append(
            model(
                investigation_id=self.id,
                seq=len(self.events) + 1,
                timestamp=datetime.now(UTC),
                payload=payload,
            )
        )

    def finish(self, status: RunStatus) -> None:
        self.append(DoneEvent, Completed(status=status))
        self.status = status


class InvestigationService:
    def __init__(
        self, store: Store, snapshot: UUID, select: Select | None = None, *, poll: float = 0.1
    ) -> None:
        self.store = store
        self.snapshot = snapshot
        self.select = select
        self.poll = poll
        self.slots = asyncio.Semaphore(1)

    def get(self, identifier: UUID, owner: str) -> Record:
        stored = self.store.get(str(identifier))
        if stored is None:
            raise ServiceError("not_found", "investigation was not found", 404)
        record = Record.model_validate_json(stored.data)
        if record.owner != owner:
            raise ServiceError("not_found", "investigation was not found", 404)
        return record

    def start(
        self, workspace: str, subject: str, key: str, request: Request, after: int
    ) -> tuple[Record, bool]:
        if request.snapshot_id is not None and request.snapshot_id != self.snapshot:
            raise ServiceError("snapshot_mismatch", "requested snapshot is not served here", 409)
        identifier = identity_key(workspace, subject, key)
        digest = hashlib.sha256(request.model_dump_json().encode()).hexdigest()
        owner = owner_key(workspace, subject)
        record = Record(
            id=identifier,
            owner=owner,
            digest=digest,
            snapshot=self.snapshot,
            trace=uuid4(),
            expires=datetime.now(UTC) + timedelta(seconds=RUN_SECONDS + 5),
        )
        record.append(StartEvent, Started(snapshot_id=record.snapshot, trace_id=record.trace))
        key_exists = self.store.get(str(identifier)) is not None
        if after and not key_exists:
            raise ServiceError("invalid_cursor", "replay requires an existing investigation", 409)
        if not key_exists and self.store.put(
            str(identifier), record.model_dump_json().encode(), None
        ):
            return record, True
        current = self.get(identifier, owner)
        if current.digest != digest or current.snapshot != self.snapshot:
            raise ServiceError("idempotency_conflict", "key was used for a different request", 409)
        if after > len(current.events):
            raise ServiceError("invalid_cursor", "event cursor is ahead of the checkpoint", 409)
        return current, False

    def mutate(self, record: Record, update: Callable[[Record], None]) -> Record:
        for _ in range(3):
            stored = self.store.get(str(record.id))
            if stored is None:
                raise ServiceError("not_found", "investigation checkpoint was not found", 503)
            current = Record.model_validate_json(stored.data)
            if current.owner != record.owner:
                raise ServiceError("not_found", "investigation was not found", 404)
            if current.status != "running":
                return current
            update(current)
            if self.store.put(str(current.id), current.model_dump_json().encode(), stored.token):
                return current
        raise ServiceError("checkpoint_conflict", "checkpoint update conflicted", 503)

    async def cancel(self, identifier: UUID, owner: str) -> Record:
        record = await asyncio.to_thread(self.get, identifier, owner)
        return await asyncio.to_thread(self.mutate, record, lambda item: item.finish("cancelled"))

    async def run(
        self,
        record: Record,
        request: Request,
        subject: str,
        app: ASGIApp,
        auth: str,
        peer: str,
    ) -> None:
        async def emit(model: type, payload: BaseModel) -> None:
            current = await asyncio.to_thread(
                self.mutate, record, lambda item: item.append(model, payload)
            )
            if current.status != "running":
                raise asyncio.CancelledError

        async def checkpoint(state: dict[str, Any]) -> None:
            current = await asyncio.to_thread(
                self.mutate, record, lambda item: setattr(item, "checkpoint", state)
            )
            if current.status != "running":
                raise asyncio.CancelledError

        try:
            async with (
                asyncio.timeout(RUN_SECONDS),
                self.slots,
                connect_tools(app, auth, peer) as tools,
            ):
                report, analytics, proposal = await execute(
                    {
                        "investigation_id": record.id,
                        "user_id": subject,
                        "trace_id": record.trace,
                        "snapshot_id": record.snapshot,
                        "request": request,
                        "revision_count": 0,
                    },
                    tools,
                    self.select,
                    emit,
                    checkpoint,
                )

                def done(item: Record) -> None:
                    if proposal:
                        item.append(ProposalEvent, proposal)
                    item.append(AnalyticsEvent, analytics)
                    item.append(ReportEvent, report)
                    item.finish("completed")

                await asyncio.to_thread(self.mutate, record, done)
        except asyncio.CancelledError:
            await asyncio.to_thread(self.mutate, record, lambda item: item.finish("cancelled"))
            raise
        except Exception as error:
            failure: BaseException = error
            while isinstance(failure, BaseExceptionGroup):
                failure = failure.exceptions[0]
            timeout = isinstance(failure, TimeoutError)
            code = (
                "timeout"
                if timeout
                else failure.code
                if isinstance(failure, ServiceError)
                else "investigation_failed"
            )
            LOGGER.warning("investigation failed trace=%s code=%s", record.trace, code)

            def failed(item: Record) -> None:
                item.append(
                    ErrorEvent, ErrorPayload(code=code, message="Investigation could not finish.")
                )
                item.finish("failed")

            await asyncio.to_thread(self.mutate, record, failed)

    async def stream(
        self, initial: Record, after: int, task: asyncio.Task[None] | None
    ) -> AsyncIterator[bytes]:
        cursor = after
        heartbeat = asyncio.get_running_loop().time() + HEARTBEAT_SECONDS
        try:
            while True:
                current = await asyncio.to_thread(self.get, initial.id, initial.owner)
                if current.status == "running" and datetime.now(UTC) > current.expires:
                    current = await asyncio.to_thread(
                        self.mutate, current, lambda item: item.finish("interrupted")
                    )
                for event in current.events[cursor:]:
                    cursor = event.seq
                    frame = f"id: {event.seq}\nevent: {event.type}\ndata: {event.model_dump_json()}"
                    yield (frame + "\n\n").encode()
                if current.status != "running":
                    return
                now = asyncio.get_running_loop().time()
                if now >= heartbeat:
                    yield b": heartbeat\n\n"
                    heartbeat = now + HEARTBEAT_SECONDS
                await asyncio.sleep(self.poll)
        finally:
            if task is not None and not task.done():
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
