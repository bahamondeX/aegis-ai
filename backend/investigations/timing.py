"""Record bounded per-component timings without payloads or identifiers from JWTs."""

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from time import monotonic
from uuid import UUID

LOG = logging.getLogger("aegis.timing")
trace: ContextVar[UUID | None] = ContextVar("investigation_trace", default=None)


@contextmanager
def measure(component: str) -> Iterator[None]:
    identifier = trace.get()
    started = monotonic()
    try:
        yield
    finally:
        if identifier and LOG.isEnabledFor(logging.INFO):
            LOG.info(
                "investigation_timing trace=%s component=%s elapsed_ms=%.2f",
                identifier,
                component,
                (monotonic() - started) * 1000,
            )
