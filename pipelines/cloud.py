"""Cloud ingestion entrypoint and immutable snapshot transport."""

import json
import os
from datetime import date
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from uuid import UUID

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError
from pydantic import BaseModel, ConfigDict, PositiveInt, ValidationError
from pyiceberg.catalog.glue import GlueCatalog

from infra.settings import SDK_CONFIG, SECRET_KEYS
from pipelines.io import DataError, digest, snapshot_directory, write_json
from pipelines.lakehouse import commit_tables
from pipelines.publish import history_files, ingest, load_run, validate_published
from pipelines.query import create_views
from schemas.sources import Run
from schemas.tables import TABLES

LATEST = "control/latest.json"
MAX_OBJECT = 32 * 1024 * 1024


class Published(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: UUID
    score_date: date
    snapshots: dict[str, PositiveInt]

    def check(self) -> "Published":
        if self.snapshots.keys() != TABLES.keys() or any(
            value >= 2**63 for value in self.snapshots.values()
        ):
            raise DataError("cloud manifest has invalid Iceberg snapshot IDs")
        return self


class SnapshotStore:
    def __init__(self, s3: BaseClient, bucket: str) -> None:
        self.s3 = s3
        self.bucket = bucket

    def read(self, key: str, *, optional: bool = False) -> bytes | None:
        try:
            obj = self.s3.get_object(Bucket=self.bucket, Key=key)
        except self.s3.exceptions.NoSuchKey:
            if optional:
                return None
            raise DataError("cloud archive object is missing") from None
        with obj["Body"] as stream:
            if obj["ContentLength"] > MAX_OBJECT:
                raise DataError("cloud archive object exceeds size limit")
            body = stream.read(MAX_OBJECT + 1)
        if obj["Metadata"].get("sha256") != digest(body):
            raise DataError("cloud archive checksum mismatch")
        return body

    def put(self, key: str, body: bytes, *, immutable: bool = True) -> None:
        if len(body) > MAX_OBJECT:
            raise DataError("cloud archive object exceeds size limit")
        checksum = digest(body)
        try:
            self.s3.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=body,
                Metadata={"sha256": checksum},
                **({"IfNoneMatch": "*"} if immutable else {}),
            )
        except ClientError as error:
            if immutable and error.response["Error"]["Code"] == "PreconditionFailed":
                if self.read(key) == body:
                    return
                raise DataError("immutable cloud object conflicts with this run ID") from None
            raise

    def release(self, run_id: UUID | None = None) -> Published | None:
        key = LATEST if run_id is None else f"control/releases/{run_id}.json"
        body = self.read(key, optional=True)
        if body is None:
            return None
        release = Published.model_validate_json(body).check()
        if run_id is not None and release.run_id != run_id:
            raise DataError("cloud release ID differs from its key")
        return release

    def copy(self, root: Path, path: Path, *, download: bool) -> None:
        key = path.relative_to(root).as_posix()
        if download:
            if path.is_file():
                return
            body = self.read(key)
            if body is None:
                raise DataError("cloud archive object is missing")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        else:
            self.put(key, path.read_bytes())

    def copy_run(
        self, root: Path, run_id: UUID, *, download: bool, complete: bool
    ) -> tuple[Path, Run]:
        folder = snapshot_directory(root, run_id)

        def transfer(path: Path) -> None:
            self.copy(root, path, download=download)

        transfer(folder / "capture.json")
        run = load_run(folder)
        if run.run_id != run_id:
            raise DataError("cloud capture ID differs from its key")
        for capture in run.captures:
            if name := capture.raw_file:
                if name in {".", ".."} or Path(name).name != name:
                    raise DataError("unsafe archive filename")
                transfer(folder / "raw" / name)
        if complete:
            for name in TABLES:
                transfer(folder / "parquet" / f"{name}.parquet")
            transfer(folder / "manifest.json")
        return folder, run

    def transfer_snapshot(self, root: Path, run_id: UUID, *, download: bool) -> Path:
        folder, run = self.copy_run(root, run_id, download=download, complete=True)
        dependencies = set(run.epss_history.values()) | set(run.nvd_history)
        for parent in sorted(dependencies - {run_id}, key=str):
            self.copy_run(root, parent, download=download, complete=False)
        for path in history_files(root, run):
            self.copy(root, path, download=download)
        return folder


def optional_source_keys(ssm: BaseClient, prefix: str) -> tuple[str | None, str | None]:
    keys: list[str | None] = []
    for name in SECRET_KEYS:
        try:
            value = ssm.get_parameter(Name=f"{prefix}/{name}", WithDecryption=True)
        except ssm.exceptions.ParameterNotFound:
            keys.append(None)
        else:
            if value["Parameter"]["Type"] != "SecureString":
                raise DataError("source parameter is not a SecureString")
            keys.append(value["Parameter"]["Value"])
    nvd, shodan = keys
    return nvd, shodan


def publish(
    store: SnapshotStore, catalog: GlueCatalog, database: str, root: Path, folder: Path
) -> Published:
    manifest = validate_published(root, folder)
    if manifest["status"] != "ok":
        raise DataError("refusing to publish an incomplete source snapshot")
    run = load_run(folder)
    previous = store.release()
    if previous and previous.run_id == run.run_id:
        return previous
    if previous and max(run.epss_history) < previous.score_date:
        raise DataError("refusing to move the published EPSS date backwards")
    if previous:
        old = snapshot_directory(root, previous.run_id)
        store.copy(root, old / "capture.json", download=True)
        previous_run = load_run(old)
        if previous_run.started_at >= run.started_at:
            raise DataError("refusing to publish an older capture")
        if not previous_run.epss_history.keys() <= run.epss_history.keys():
            raise DataError("refusing to publish a release that drops historical EPSS days")
    # A retry can find the immutable release manifest after an interrupted
    # latest-pointer write. Reuse it without creating additional snapshots.
    release = store.release(run.run_id)
    if release is None:
        tables = {name: catalog.load_table((database, name)) for name in TABLES}
        snapshots, score_date = commit_tables(tables, root, folder)
        release = Published(run_id=run.run_id, score_date=score_date, snapshots=snapshots).check()
        store.put(f"control/releases/{run.run_id}.json", release.model_dump_json().encode())
    # Reserved concurrency serializes invocations. Readers resolve this pointer once
    # and use FOR VERSION AS OF on every relation.
    store.put(LATEST, release.model_dump_json().encode(), immutable=False)
    return release


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        return run_handler(event, context)
    except ClientError as error:
        raise RuntimeError(f"AWS operation failed: {error.response['Error']['Code']}") from None
    except ValidationError:
        raise RuntimeError("invalid cloud event or archive schema") from None


def run_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    action = event.get("action")
    if action == "ingest" and event.keys() == {"action"}:
        run_id = None
    elif action == "publish" and event.keys() == {"action", "run_id"}:
        try:
            run_id = UUID(event["run_id"])
        except (ValueError, AttributeError, TypeError):
            raise DataError("invalid staged run ID") from None
    else:
        raise DataError("invalid ingestion event")

    region = os.environ["AWS_REGION"]
    database = os.environ["AEGIS_GLUE_DATABASE"]
    bucket = os.environ["AEGIS_LAKE_BUCKET"]
    session = boto3.Session(region_name=region)
    store = SnapshotStore(session.client("s3", config=SDK_CONFIG), bucket)
    catalog = GlueCatalog(
        "aegis",
        client=session.client("glue", config=SDK_CONFIG),
        **{"s3.region": region, "s3.connect-timeout": "5", "s3.request-timeout": "30"},
    )
    with TemporaryDirectory(dir="/tmp", prefix="aegis-") as temp:
        root = Path(temp)
        if run_id is not None:
            if (current := store.release()) and current.run_id == run_id:
                return current.model_dump(mode="json")
            folder = store.transfer_snapshot(root, run_id, download=True)
            create_views(folder, history_files(root, load_run(folder)))
        else:
            if previous := store.release():
                store.transfer_snapshot(root, previous.run_id, download=True)
                write_json(root / "latest.json", {"run_id": previous.run_id})
            keys = optional_source_keys(
                session.client("ssm", config=SDK_CONFIG), os.environ["AEGIS_SSM_PATH"]
            )
            try:
                folder, manifest = ingest(
                    root, root / ".env", 20, daily_epss=True, source_keys=keys
                )
            except DataError:
                # Preserve captures with provenance even when normalization fails.
                for capture in (root / "snapshots").glob("*/failure.json"):
                    failed_id = UUID(capture.parent.name)
                    store.copy_run(root, failed_id, download=False, complete=False)
                    store.copy(root, capture, download=False)
                raise
            store.copy_run(root, UUID(folder.name), download=False, complete=True)
            if manifest["status"] != "ok":
                raise DataError("cloud ingestion was blocked by incomplete source coverage")
        if context.get_remaining_time_in_millis() < 60_000:
            raise DataError("insufficient Lambda time to start Iceberg commits")
        result = publish(store, catalog, database, root, folder)
        print(json.dumps({"event": "lake.release.published", **result.model_dump(mode="json")}))
        return result.model_dump(mode="json")
