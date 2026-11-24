"""Run the authenticated local API or exercise it against the real snapshot."""

import argparse
import os
import secrets
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import UUID

import uvicorn

from backend.api import create_app
from backend.auth import LOCAL_AUDIENCE, LOCAL_ISSUER, Auth, mint
from backend.investigations.bedrock import approved_model
from backend.investigations.contracts import Mode
from backend.investigations.service import InvestigationService
from backend.investigations.store import SQLiteStore
from backend.reader import SnapshotReader
from pipelines.config import configured_snapshot, project_environment


def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS local API")
    parser.add_argument("command", choices=("dev", "smoke", "smoke-investigation"))
    parser.add_argument("--snapshot", type=UUID)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--bedrock", action="store_true")
    parser.add_argument("--expect-fallback", action="store_true")
    args = parser.parse_args()
    if args.expect_fallback and (args.command != "smoke-investigation" or not args.bedrock):
        parser.error("--expect-fallback is available for a Bedrock investigation smoke")
    env = project_environment()
    root = Path(env.get("AEGIS_DATA_DIR") or "data").resolve()
    snapshot = args.snapshot or configured_snapshot(env)
    reader = SnapshotReader.duckdb(root, snapshot)
    key = secrets.token_urlsafe(48)
    auth = Auth(issuer=LOCAL_ISSUER, audience=LOCAL_AUDIENCE, workspace="local", local_key=key)
    store = SQLiteStore(root / "investigations.sqlite3")
    selection = approved_model(env, store) if args.bedrock else None
    app = create_app(reader, auth, InvestigationService(store, reader.snapshot, selection))
    if args.command == "smoke-investigation":
        from backend.investigations.smoke import smoke

        mode: Mode = (
            "fallback" if args.expect_fallback else "bedrock" if args.bedrock else "deterministic"
        )
        smoke(app, key, reader.snapshot, mode=mode)
        return
    if args.command == "smoke":
        from backend.smoke import verify

        verify(app, key, reader, root)
        return
    with NamedTemporaryFile(dir=root, prefix=".local-api-", delete=False) as file:
        os.fchmod(file.fileno(), 0o600)
        file.write(mint(key).encode() + b"\n")
    target = root / "local-api.token"
    os.replace(file.name, target)
    print(f"AEGIS API http://127.0.0.1:{args.port} | 15-minute bearer token: {target}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=args.port, proxy_headers=False)


if __name__ == "__main__":
    main()
