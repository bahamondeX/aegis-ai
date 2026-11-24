"""Conditional durable storage for investigation records and model reservations."""

import json
import os
import sqlite3
import stat
from contextlib import closing
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from backend.models import ServiceError

MAX_RECORD = 256 * 1024


@dataclass(frozen=True)
class Version:
    data: bytes
    token: str


class Store(Protocol):
    def get(self, key: str) -> Version | None: ...

    def put(self, key: str, data: bytes, expected: str | None) -> bool: ...


class SQLiteStore:
    """Local process-independent journal. Contents and sidecars stay under data/."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
                raise ValueError("investigation database must have permissions 600")
        finally:
            os.close(descriptor)
        self.path = path
        with closing(sqlite3.connect(self.path, timeout=2)) as db, db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS checkpoint ("
                "key TEXT PRIMARY KEY, token TEXT NOT NULL, content BLOB NOT NULL)"
            )

    def get(self, key: str) -> Version | None:
        with closing(sqlite3.connect(self.path, timeout=2)) as db:
            row = db.execute("SELECT content, token FROM checkpoint WHERE key=?", (key,)).fetchone()
        return Version(*row) if row else None

    def put(self, key: str, data: bytes, expected: str | None) -> bool:
        if len(data) > MAX_RECORD:
            raise ServiceError("checkpoint_limit", "checkpoint exceeds its size budget", 503)
        token = uuid4().hex
        with closing(sqlite3.connect(self.path, timeout=2)) as db, db:
            if expected is None:
                cursor = db.execute(
                    "INSERT INTO checkpoint VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
                    (key, token, data),
                )
            else:
                cursor = db.execute(
                    "UPDATE checkpoint SET content=?, token=? WHERE key=? AND token=?",
                    (data, token, key, expected),
                )
            return cursor.rowcount == 1


class S3Store:
    """Cross-session journal using an owned KMS-encrypted bucket and S3 compare-and-set."""

    def __init__(
        self,
        client: BaseClient,
        bucket: str,
        owner: str,
        key_id: str,
        *,
        namespace: str = "checkpoints",
    ) -> None:
        self.client = client
        self.bucket = bucket
        self.owner = owner
        self.key_id = key_id
        self.namespace = namespace

    def object_key(self, key: str) -> str:
        if self.namespace != "checkpoints":
            return f"{self.namespace}/{key}.json"
        prefix = "ledger" if key == "bedrock-spend" else "run"
        return f"checkpoints/{prefix}/{key}.json"

    def get(self, key: str) -> Version | None:
        try:
            obj = self.client.get_object(
                Bucket=self.bucket,
                Key=self.object_key(key),
                ExpectedBucketOwner=self.owner,
            )
        except self.client.exceptions.NoSuchKey:
            return None
        with obj["Body"] as stream:
            if (
                obj["ContentLength"] > MAX_RECORD
                or obj.get("ServerSideEncryption") != "aws:kms"
                or obj.get("SSEKMSKeyId") != self.key_id
            ):
                raise ServiceError("checkpoint_integrity", "invalid checkpoint object", 503)
            return Version(stream.read(MAX_RECORD + 1), obj["ETag"])

    def put(self, key: str, data: bytes, expected: str | None) -> bool:
        if len(data) > MAX_RECORD:
            raise ServiceError("checkpoint_limit", "checkpoint exceeds its size budget", 503)
        condition = {"IfMatch": expected} if expected else {"IfNoneMatch": "*"}
        try:
            self.client.put_object(
                Bucket=self.bucket,
                Key=self.object_key(key),
                ExpectedBucketOwner=self.owner,
                ServerSideEncryption="aws:kms",
                SSEKMSKeyId=self.key_id,
                Body=data,
                **condition,
            )
        except ClientError as error:
            if error.response["Error"]["Code"] in {
                "PreconditionFailed",
                "ConditionalRequestConflict",
            }:
                return False
            raise
        return True


def reserve(store: Store, key: str, charge: Decimal, ceiling: Decimal) -> None:
    """Reserve worst-case cost before each model attempt, including retries."""
    for _ in range(3):
        previous = store.get(key)
        spent = Decimal(json.loads(previous.data)["reserved_usd"]) if previous else Decimal(0)
        if spent + charge > ceiling:
            raise ServiceError(
                "model_budget", "Bedrock reservation exceeds the approved ceiling", 429
            )
        body = json.dumps({"reserved_usd": str(spent + charge)}).encode()
        if store.put(key, body, previous.token if previous else None):
            return
    raise ServiceError("checkpoint_conflict", "unable to reserve model budget", 503)
