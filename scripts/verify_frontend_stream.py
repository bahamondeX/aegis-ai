"""Exercise the compiled browser client against the real loopback API."""

import secrets
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from backend.api import create_app
from backend.auth import LOCAL_AUDIENCE, LOCAL_ISSUER, Auth, mint
from backend.investigations.service import InvestigationService
from backend.investigations.store import SQLiteStore
from backend.reader import SnapshotReader
from backend.smoke import live_server
from pipelines.config import ROOT, configured_snapshot, project_environment


def main() -> None:
    environment = project_environment()
    root = Path(environment.get("AEGIS_DATA_DIR") or "data").resolve()
    reader = SnapshotReader.duckdb(root, configured_snapshot(environment))
    with TemporaryDirectory(dir=root) as directory:
        path = Path(directory)
        key = secrets.token_urlsafe(48)
        auth = Auth(issuer=LOCAL_ISSUER, audience=LOCAL_AUDIENCE, workspace="local", local_key=key)
        token = path / "token"
        token.touch(mode=0o600)
        token.write_text(mint(key), encoding="utf-8")
        service = InvestigationService(SQLiteStore(path / "journal.db"), reader.snapshot)
        with live_server(create_app(reader, auth, service)) as base:
            subprocess.run(
                ["node", str(ROOT / "frontend/tests/live-sse.mjs"), base, str(token)],
                check=True,
                timeout=60,
            )


if __name__ == "__main__":
    main()
