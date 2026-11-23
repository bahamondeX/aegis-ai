import fcntl
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import duckdb
import pyarrow.parquet as pq
from pyarrow import ArrowException
from pydantic import ValidationError

from pipelines.fetch import run_capture
from pipelines.io import DataError, selected_snapshot, snapshot_directory, write_json
from pipelines.normalize import normalize
from pipelines.query import Query, connect, create_views, query
from pipelines.validate import validate
from schemas.sources import SCHEMA_VERSION, Run


def load_run(folder: Path) -> Run:
    return Run.model_validate_json((folder / "capture.json").read_bytes())


def history_files(root: Path, run: Run) -> list[Path]:
    return [
        snapshot_directory(root, run_id) / "parquet" / "fact_epss.parquet"
        for _, run_id in sorted(run.epss_history.items())
        if run_id != run.run_id
    ]


def materialize(root: Path, raw_folder: Path, output: Path, run: Run) -> dict[str, Any]:
    tables = normalize(root, raw_folder, run)
    parquet = output / "parquet"
    parquet.mkdir()
    for name, table in tables.items():
        pq.write_table(table, parquet / f"{name}.parquet", compression="zstd")
    create_views(output, history_files(root, run))
    return validate(root, output, run)


def ingest(root: Path, env_file: Path, limit: int) -> tuple[Path, dict[str, Any]]:
    root.mkdir(exist_ok=True, parents=True)
    with (root / ".ingest.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DataError("another ingestion holds the local writer lock") from None
        previous = load_run(selected_snapshot(root)) if (root / "latest.json").is_file() else None
        folder, run = run_capture(root, previous, limit, env_file)
        status = "ok" if run.nvd_found else "blocked"
        manifest: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "run_id": str(run.run_id),
            "status": status,
            "capture": "capture.json",
            "cohort": "CISA KEV at the pinned catalog release",
            "geometry": {"status": "unavailable", "reason": run.shodan_status},
        }
        try:
            manifest.update(materialize(root, folder, folder, run))
        except (DataError, OSError, ValidationError, ArrowException, duckdb.Error) as error:
            detail = str(error) if isinstance(error, DataError) else type(error).__name__
            write_json(folder / "failure.json", {"run_id": run.run_id, "error": detail})
            raise DataError(f"{detail}; capture preserved at {folder}") from None
        # Immutable run files precede the manifest. Readers only discover completed runs.
        write_json(folder / "manifest.json", manifest)
        if status == "ok":
            write_json(root / "latest.json", {"run_id": run.run_id})
        return folder, manifest


def validate_published(root: Path, folder: Path) -> dict[str, Any]:
    run = load_run(folder)
    manifest = json.loads((folder / "manifest.json").read_text())
    checked = validate(root, folder, run)
    calculated_status = "ok" if run.nvd_found else "blocked"
    if (
        manifest["run_id"] != str(run.run_id)
        or manifest["schema_version"] != SCHEMA_VERSION
        or manifest["status"] != calculated_status
        or any(manifest[key] != value for key, value in checked.items())
    ):
        raise DataError("published snapshot differs from validated manifest")
    return manifest


def verify_replay(root: Path, folder: Path, manifest: dict[str, Any]) -> None:
    run = load_run(folder)
    with TemporaryDirectory(dir=root, prefix=".verify-") as temporary:
        output = Path(temporary)
        replayed = materialize(root, folder, output, run)
        if any(manifest[key] != value for key, value in replayed.items()):
            raise DataError("same-snapshot replay differs from published results")
        with (
            connect(folder / "aegis.duckdb") as published,
            connect(output / "aegis.duckdb") as rebuilt,
        ):
            for template in Query:
                if query(published, template, limit=1000) != query(rebuilt, template, limit=1000):
                    raise DataError(f"same-snapshot replay differs for {template.value}")
