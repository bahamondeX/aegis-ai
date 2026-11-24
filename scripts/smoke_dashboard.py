"""Run Playwright against a Nuxt production build and the real authenticated local API."""

import argparse
import json
import os
import secrets
import socket
import subprocess
import time
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from backend.api import create_app
from backend.auth import LOCAL_AUDIENCE, LOCAL_ISSUER, Auth, mint
from backend.investigations.service import InvestigationService
from backend.investigations.store import SQLiteStore
from backend.reader import SnapshotReader
from backend.smoke import live_server
from infra.settings import Settings
from pipelines.config import ROOT, configured_snapshot, project_environment


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cognito", action="store_true")
    parser.add_argument("--evidence-dir", default="evidence/g5")
    args = parser.parse_args()
    configuration = project_environment()
    root = Path(configuration.get("AEGIS_DATA_DIR") or "data").resolve()
    reader = SnapshotReader.duckdb(root, configured_snapshot(configuration))
    node_pin = (ROOT / ".nvmrc").read_text().strip()
    frontend = ROOT / "frontend"
    artifact = frontend / ".output/server/index.mjs"
    if not artifact.is_file():
        raise SystemExit("Build the Nuxt production artifact first")
    evidence = root / args.evidence_dir
    evidence.mkdir(parents=True, exist_ok=True)
    local_node = root / "toolchain" / f"node-{node_pin}" / "bin/node"
    node = str(local_node) if local_node.is_file() else "node"
    key = secrets.token_urlsafe(48)
    auth = Auth(issuer=LOCAL_ISSUER, audience=LOCAL_AUDIENCE, workspace="local", local_key=key)
    fixture_path = root / "evidence/agentcore/private/fixture.json"
    cognito_environment: dict[str, str] = {}
    if args.cognito:
        from backend.investigations.bedrock import bedrock_allocations, read_amount

        settings = Settings.load(environment=configuration)
        scope = f"{settings.account}/{settings.region}/{settings.project}"
        if (
            configuration.get("AEGIS_AGENTCORE_APPROVAL") != f"{scope}/agentcore"
            or configuration.get("AEGIS_BEDROCK_APPROVAL") != f"{scope}/bedrock"
        ):
            raise SystemExit("Approved AgentCore and Bedrock scopes are required")
        bedrock_allocations(configuration)
        read_amount(configuration, "AEGIS_AGENTCORE_BUDGET_USD")
        settings.authorize()
        settings.identity()
        fixture = json.loads(fixture_path.read_text())
        if fixture["snapshot"] != str(reader.snapshot):
            raise SystemExit("The local and deployed releases must agree")
        issuer = fixture["issuer"]
        auth = Auth(
            issuer=issuer,
            audience=fixture["client"],
            workspace=settings.project,
            jwks_url=f"{issuer}/.well-known/jwks.json",
            cognito=True,
        )
        countfile = fixture_path.with_name("validation-calls.log")
        if len(countfile.read_text().splitlines()) >= 20:
            raise SystemExit("Cloud validation exceeded the fixed invocation allowance")
        with countfile.open("a") as log:
            log.write("cognito-frontend-agent\n")
        cognito_environment = {
            "NUXT_PUBLIC_COGNITO_ISSUER": issuer,
            "NUXT_PUBLIC_COGNITO_CLIENT_ID": fixture["client"],
            "NUXT_PUBLIC_COGNITO_DOMAIN": fixture["domain"],
            "NUXT_AEGIS_RUNTIME_URL": fixture["runtime"],
            "AEGIS_BROWSER_COGNITO_FIXTURE": str(fixture_path),
        }

    with TemporaryDirectory(prefix="aegis-g5-") as directory:
        scratch = Path(directory)
        token = scratch / "access.token"
        token.touch(mode=0o600)
        token.write_text(mint(key), encoding="utf-8")
        graph = InvestigationService(SQLiteStore(scratch / "journal.db"), reader.snapshot)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = str(sock.getsockname()[1])
        host, port = ("localhost", "3000") if args.cognito else ("127.0.0.1", port)
        base = f"http://{host}:{port}"
        with live_server(create_app(reader, auth, graph)) as api:
            environment = {
                **os.environ,
                "NUXT_AEGIS_API_BASE": api,
                "NITRO_PORT": port,
                "NITRO_HOST": host,
                "AEGIS_BROWSER_URL": base,
                "AEGIS_BROWSER_TOKEN_FILE": str(token),
                "AEGIS_BROWSER_EVIDENCE": str(evidence),
                "NUXT_PUBLIC_COGNITO_ISSUER": "",
                "NUXT_PUBLIC_COGNITO_CLIENT_ID": "",
                "NUXT_PUBLIC_COGNITO_DOMAIN": "",
                "NUXT_AEGIS_RUNTIME_URL": "",
                **cognito_environment,
            }
            with (evidence / "nuxt-server.log").open("w") as log:
                server = subprocess.Popen(
                    [node, str(artifact)],
                    env=environment,
                    cwd=frontend,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
                try:
                    deadline = time.monotonic() + 25
                    with httpx.Client(trust_env=False, timeout=2) as client:
                        while time.monotonic() < deadline and server.poll() is None:
                            try:
                                if client.get(f"{base}/api/aegis/health").status_code == 200:
                                    break
                            except httpx.TransportError:
                                pass
                            time.sleep(0.3)
                        else:
                            raise RuntimeError("Nuxt application did not start")
                    subprocess.run(
                        [
                            node,
                            "node_modules/@playwright/test/cli.js",
                            "test",
                            "cognito.spec.ts" if args.cognito else "dashboard.spec.ts",
                        ],
                        check=True,
                        cwd=frontend,
                        env=environment,
                        timeout=280,
                    )
                finally:
                    if server.poll() is None:
                        server.terminate()
                        server.wait(timeout=8)


if __name__ == "__main__":
    main()
