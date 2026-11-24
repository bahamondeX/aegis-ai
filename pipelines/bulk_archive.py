"""Bounded, resumable downloads for official V2 public archives."""

import gzip
import hashlib
import random
import shutil
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict

import httpx

from pipelines.fetch import MAX_ATTEMPTS, retry_after
from pipelines.io import DataError, file_digest

CHUNK = 1024 * 1024
DISK_RESERVE = 1024 * 1024 * 1024
TRANSFER_LIMIT = 1024 * 1024 * 1024


class TransferReceipt(TypedDict):
    bytes: int
    sha256: str
    retrieved_at: str
    etag: str | None


@dataclass(frozen=True)
class Archive:
    source: str
    key: str
    uri: str
    revision: str
    published_at: datetime
    length: int | None = None
    sha256: str | None = None
    uncompressed_length: int | None = None
    uncompressed_sha256: str | None = None
    metadata_uri: str | None = None

    def folder(self, root: Path) -> Path:
        return root / self.source / self.key / self.revision


def check_space(path: Path, incoming: int = 0) -> None:
    if shutil.disk_usage(path).free < DISK_RESERVE + incoming:
        raise DataError("V2 local storage reached its 1 GiB free-space reserve")


def transfer(
    client: httpx.Client,
    uri: str,
    path: Path,
    limit: int,
    expected: int | None = None,
) -> TransferReceipt:
    """Stream atomically and keep only complete HTTP payloads."""
    partial = path.with_suffix(".part")
    for attempt in range(MAX_ATTEMPTS):
        delay = 0.0
        started = time.monotonic()
        offset = partial.stat().st_size if expected is not None and partial.is_file() else 0
        if expected is not None and not 0 <= offset < expected:
            partial.unlink(missing_ok=True)
            offset = 0
        try:
            headers = {"Range": f"bytes={offset}-"} if offset else None
            with client.stream("GET", uri, headers=headers) as response:
                code = response.status_code
                if code in (200, 206):
                    start = offset if code == 206 else 0
                    if code == 206 and (
                        not start
                        or expected is None
                        or response.headers.get("Content-Range")
                        != f"bytes {start}-{expected - 1}/{expected}"
                    ):
                        raise DataError("provider returned an unexpected byte range")
                    declared = response.headers.get("Content-Length")
                    size_hint = int(declared) if declared and declared.isdecimal() else None
                    if size_hint is not None and start + size_hint > limit:
                        raise DataError("provider payload exceeds the bounded transfer size")
                    incoming = expected - start if expected is not None else size_hint or 0
                    check_space(path.parent, incoming)
                    received = start
                    deadline = 900 if limit > 128 * CHUNK else 300
                    with partial.open("ab" if start else "wb") as stream:
                        for chunk in response.iter_bytes(chunk_size=CHUNK):
                            received += len(chunk)
                            if received > limit or time.monotonic() - started > deadline:
                                raise DataError("provider payload exceeded the transfer bound")
                            check_space(path.parent, len(chunk))
                            stream.write(chunk)
                    if expected is not None and received != expected:
                        raise DataError(
                            f"provider payload size mismatch, expected {expected}, got {received}"
                        )
                    partial.replace(path)
                    return {
                        "bytes": received,
                        "sha256": file_digest(path),
                        "retrieved_at": datetime.now(UTC).isoformat(),
                        "etag": response.headers.get("ETag"),
                    }
                error = f"HTTP {code}"
                if code != 429 and not 500 <= code <= 599:
                    raise DataError(f"public archive retrieval failed with {error}")
                delay = retry_after(response.headers.get("Retry-After"))
        except httpx.TransportError as exc:
            error = type(exc).__name__
        finally:
            if expected is None:
                partial.unlink(missing_ok=True)
        if attempt == MAX_ATTEMPTS - 1 or delay > 30:
            raise DataError(f"public archive retrieval failed with {error}")
        time.sleep(max(delay, 2**attempt + random.uniform(0, 0.5)))
    raise AssertionError("transfer retry loop did not terminate")


def verify_archive(archive: Archive, path: Path, sha256: str) -> None:
    if archive.sha256 and sha256 != archive.sha256:
        raise DataError("archive SHA-256 differs from the provider manifest")
    if archive.uncompressed_sha256 is None:
        return
    size = 0
    digest = hashlib.sha256()
    with gzip.open(path, "rb") as stream:
        while chunk := stream.read(CHUNK):
            size += len(chunk)
            if archive.uncompressed_length is not None and size > archive.uncompressed_length:
                raise DataError("NVD decompressed size exceeds its META record")
            digest.update(chunk)
    if size != archive.uncompressed_length or digest.hexdigest() != archive.uncompressed_sha256:
        raise DataError("NVD decompressed size or SHA-256 differs from its META record")


def verify_receipt(path: Path, receipt: dict) -> bool:
    raw = path / "payload"
    parquet = path / "records.parquet"
    return (
        raw.is_file()
        and parquet.is_file()
        and raw.stat().st_size == receipt["raw"]["bytes"]
        and parquet.stat().st_size == receipt["normalized_bytes"]
        and file_digest(raw) == receipt["raw"]["sha256"]
        and file_digest(parquet) == receipt["normalized_sha256"]
    )
