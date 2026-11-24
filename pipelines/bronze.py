"""Immutable V2 object storage shared by migration and ingestion."""

import base64
import json
import os
import re
import shutil
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from pipelines.io import DataError, digest, file_digest

PREFIX = "v2/bronze"
OBJECT_LIMIT = 1024**3
RECEIPT_LIMIT = 8 * 1024**2


def object_key(key: str) -> str:
    path = PurePosixPath(key)
    if (
        not key.startswith(PREFIX + "/")
        or path.as_posix() != key
        or ".." in path.parts
        or len(key) > 900
        or not re.fullmatch(r"[A-Za-z0-9_.=/\-]+", key)
    ):
        raise DataError("invalid V2 object key")
    return key


@dataclass(frozen=True)
class ObjectRef:
    key: str
    size: int
    sha256: str
    version_id: str | None = None

    def __post_init__(self) -> None:
        object_key(self.key)
        if not re.fullmatch(r"[a-f0-9]{64}", self.sha256) or not 0 <= self.size <= OBJECT_LIMIT:
            raise DataError("invalid V2 object checksum or size")

    @property
    def checksum(self) -> str:
        return base64.b64encode(bytes.fromhex(self.sha256)).decode("ascii")

    def matches(self, other: "ObjectRef") -> bool:
        return (self.key, self.size, self.sha256) == (other.key, other.size, other.sha256)


def artifact(source: str, kind: str, path: Path) -> ObjectRef:
    checksum = file_digest(path)
    return ObjectRef(f"{PREFIX}/{source}/{kind}/{checksum}", path.stat().st_size, checksum)


class BronzeStore(Protocol):
    def inspect(self, key: str) -> ObjectRef | None: ...

    def put_once(self, ref: ObjectRef, file: Path) -> bool: ...

    def read(self, key: str) -> bytes | None: ...


def ensure(store: BronzeStore, ref: ObjectRef, file: Path) -> tuple[ObjectRef, bool]:
    current = store.inspect(ref.key)
    wrote = False
    if current is None:
        wrote = store.put_once(ref, file)
        current = store.inspect(ref.key)
    if current is None or not ref.matches(current):
        raise DataError("immutable object differs from its planned checksum or size")
    return current, wrote


def record(store: BronzeStore, key: str) -> dict | None:
    raw = store.read(key)
    return json.loads(raw) if raw is not None else None


def put_record(store: BronzeStore, key: str, value: dict, *, exact: bool = True) -> bool:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > RECEIPT_LIMIT:
        raise DataError("V2 control record exceeds its byte limit")
    with tempfile.TemporaryDirectory() as scratch:
        file = Path(scratch) / "receipt"
        file.write_bytes(raw)
        ref = ObjectRef(key, len(raw), digest(raw))
        if exact:
            _, wrote = ensure(store, ref, file)
            return wrote
        return store.put_once(ref, file)


class LocalBronze:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def path(self, key: str) -> Path:
        result = self.root / object_key(key)
        if not result.resolve().is_relative_to(self.root):
            raise DataError("V2 object escapes the local storage root")
        return result

    def inspect(self, key: str) -> ObjectRef | None:
        file = self.path(key)
        if not file.is_file():
            return None
        return ObjectRef(key, file.stat().st_size, file_digest(file))

    def put_once(self, ref: ObjectRef, file: Path) -> bool:
        target = self.path(ref.key)
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=target.parent) as scratch:
            staged = Path(scratch) / "object"
            shutil.copyfile(file, staged)
            if staged.stat().st_size != ref.size or file_digest(staged) != ref.sha256:
                raise DataError("local artifact changed during transfer")
            try:
                os.link(staged, target)
            except FileExistsError:
                return False
        return True

    def read(self, key: str) -> bytes | None:
        file = self.path(key)
        try:
            with file.open("rb") as stream:
                raw = stream.read(RECEIPT_LIMIT + 1)
        except FileNotFoundError:
            return None
        if len(raw) > RECEIPT_LIMIT:
            raise DataError("V2 control record exceeds its byte limit")
        return raw


class S3Bronze:
    def __init__(self, client: BaseClient, bucket: str, owner: str, kms_key: str) -> None:
        self.client, self.bucket, self.owner, self.kms_key = client, bucket, owner, kms_key

    def parameters(self, key: str) -> dict:
        return {"Bucket": self.bucket, "Key": object_key(key), "ExpectedBucketOwner": self.owner}

    def missing(self, error: ClientError, key: str) -> bool:
        code = error.response["Error"]["Code"]
        if code in {"404", "NoSuchKey", "NotFound"}:
            return True
        if code not in {"403", "AccessDenied"}:
            return False
        # A prefix-scoped role may receive 403 instead of 404 on a missing object.
        listing = self.client.list_objects_v2(
            Bucket=self.bucket,
            Prefix=key,
            MaxKeys=1,
            ExpectedBucketOwner=self.owner,
        )
        # An exact key sorts ahead of any longer key beginning with that prefix.
        return not any(row["Key"] == key for row in listing.get("Contents", []))

    def inspect(self, key: str) -> ObjectRef | None:
        try:
            head = self.client.head_object(**self.parameters(key), ChecksumMode="ENABLED")
        except ClientError as error:
            if self.missing(error, key):
                return None
            raise
        checksum = head.get("ChecksumSHA256")
        if (
            not checksum
            or head.get("ChecksumType", "FULL_OBJECT") != "FULL_OBJECT"
            or head.get("ServerSideEncryption") != "aws:kms"
            or head.get("SSEKMSKeyId") != self.kms_key
            or head.get("VersionId") in {None, "", "null"}
        ):
            raise DataError("V2 object is missing the expected checksum, encryption, or version")
        return ObjectRef(
            key,
            head["ContentLength"],
            base64.b64decode(checksum, validate=True).hex(),
            head["VersionId"],
        )

    def put_once(self, ref: ObjectRef, file: Path) -> bool:
        with file.open("rb") as stream:
            try:
                self.client.put_object(
                    **self.parameters(ref.key),
                    Body=stream,
                    ContentLength=ref.size,
                    ChecksumSHA256=ref.checksum,
                    IfNoneMatch="*",
                    ServerSideEncryption="aws:kms",
                    SSEKMSKeyId=self.kms_key,
                    BucketKeyEnabled=True,
                )
            except ClientError as error:
                if error.response["Error"]["Code"] in {"412", "PreconditionFailed"}:
                    return False
                raise
        return True

    def read(self, key: str) -> bytes | None:
        try:
            obj = self.client.get_object(**self.parameters(key), ChecksumMode="ENABLED")
        except ClientError as error:
            if self.missing(error, key):
                return None
            raise
        with obj["Body"] as body:
            if obj["ContentLength"] > RECEIPT_LIMIT:
                raise DataError("V2 control record exceeds its byte limit")
            raw = body.read(RECEIPT_LIMIT + 1)
        if (
            len(raw) != obj["ContentLength"]
            or obj.get("ChecksumSHA256") != base64.b64encode(bytes.fromhex(digest(raw))).decode()
            or obj.get("ServerSideEncryption") != "aws:kms"
            or obj.get("SSEKMSKeyId") != self.kms_key
            or obj.get("VersionId") in {None, "", "null"}
        ):
            raise DataError("V2 control record failed integrity validation")
        return raw


def refs_json(refs: list[ObjectRef]) -> list[dict]:
    return [asdict(ref) for ref in refs]
