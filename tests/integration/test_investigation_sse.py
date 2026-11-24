"""Verify both HTTP entrypoints over real loopback TCP against a capture."""

import os
import secrets
from pathlib import Path
from uuid import UUID

import pytest

from backend.api import create_app
from backend.auth import LOCAL_AUDIENCE, LOCAL_ISSUER, Auth
from backend.investigations.service import InvestigationService
from backend.investigations.smoke import smoke
from backend.investigations.store import SQLiteStore
from backend.reader import SnapshotReader

pytestmark = pytest.mark.live


@pytest.mark.parametrize("runtime", [False, True], ids=["api", "agentcore-http"])
def test_real_snapshot_investigation(tmp_path: Path, runtime: bool) -> None:
    root = Path(os.environ["AEGIS_DATA_DIR"])
    reader = SnapshotReader.duckdb(root, UUID(os.environ["AEGIS_SNAPSHOT"]))
    key = secrets.token_urlsafe(48)
    auth = Auth(issuer=LOCAL_ISSUER, audience=LOCAL_AUDIENCE, workspace="local", local_key=key)
    service = InvestigationService(SQLiteStore(tmp_path / "journal.db"), reader.snapshot)
    smoke(create_app(reader, auth, service, runtime=runtime), key, reader.snapshot, runtime=runtime)
