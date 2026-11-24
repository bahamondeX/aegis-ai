"""Verify the built static workspace and PKCE initiation without calling AWS."""

import os
import subprocess
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from pipelines.config import ROOT


def main() -> None:
    dist = ROOT / "frontend/.output/public"
    if not (dist / "auth/callback/index.html").is_file():
        raise SystemExit("Build the static workspace first")
    evidence = ROOT / "data/evidence/continuation"
    evidence.mkdir(parents=True, exist_ok=True)
    with ThreadingHTTPServer(
        ("127.0.0.1", 0), partial(SimpleHTTPRequestHandler, directory=str(dist))
    ) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            subprocess.run(
                ["sh", "scripts/frontend.sh", "browser", "static_hosting.spec.ts"],
                cwd=ROOT,
                env={
                    **os.environ,
                    "AEGIS_BROWSER_URL": f"http://127.0.0.1:{server.server_port}",
                    "AEGIS_BROWSER_STATIC": "1",
                    "AEGIS_BROWSER_EVIDENCE": str(evidence),
                },
                check=True,
                timeout=65,
            )
        finally:
            server.shutdown()
            worker.join()


if __name__ == "__main__":
    main()
