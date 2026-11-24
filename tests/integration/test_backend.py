"""Network smoke for G3 against the same published snapshot as the data gate."""

import os
import secrets
from pathlib import Path
from uuid import UUID

import pytest

from backend.api import create_app
from backend.auth import LOCAL_AUDIENCE, LOCAL_ISSUER, Auth
from backend.reader import SnapshotReader
from backend.smoke import verify

pytestmark = pytest.mark.live


def test_rest_and_mcp_over_loopback() -> None:
    root = Path(os.environ["AEGIS_DATA_DIR"])
    reader = SnapshotReader.duckdb(root, UUID(os.environ["AEGIS_SNAPSHOT"]))
    key = secrets.token_urlsafe(48)
    auth = Auth(issuer=LOCAL_ISSUER, audience=LOCAL_AUDIENCE, workspace="local", local_key=key)
    verify(create_app(reader, auth), key, reader, root)
