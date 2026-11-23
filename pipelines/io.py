import hashlib
import json
import os
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel

from schemas.sources import Capture


class DataError(Exception):
    """A sanitized ingestion or validation error."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def write_json(path: Path, value: BaseModel | dict) -> None:
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        if isinstance(value, BaseModel):
            handle.write(value.model_dump_json(indent=2))
        else:
            json.dump(value, handle, indent=2, sort_keys=True, default=str)
        handle.write("\n")
    os.replace(temporary, path)


def read_raw(folder: Path, capture: Capture) -> bytes:
    if capture.raw_file is None or capture.checksum is None:
        raise DataError(f"{capture.source}: raw payload metadata missing")
    path = folder / "raw" / capture.raw_file
    if path.parent != folder / "raw" or not path.is_file():
        raise DataError(f"{capture.source}: raw payload missing")
    data = path.read_bytes()
    if digest(data) != capture.checksum:
        raise DataError(f"{capture.source}: raw payload checksum mismatch")
    return data


def snapshot_directory(root: Path, run_id: UUID) -> Path:
    return root / "snapshots" / str(run_id)


def selected_snapshot(root: Path, run_id: UUID | None = None) -> Path:
    if run_id is None:
        pointer = root / "latest.json"
        if not pointer.is_file():
            raise DataError("no current snapshot; run make ingest-local")
        run_id = UUID(json.loads(pointer.read_text())["run_id"])
    return snapshot_directory(root, run_id)


def capture_for(captures: list[Capture], source: str) -> Capture | None:
    return next(
        (capture for capture in reversed(captures) if capture.source == source),
        None,
    )
