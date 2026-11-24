"""Build an authenticated static Nuxt artifact using public Cognito metadata only."""

import os
import re
import subprocess
from pathlib import Path

from pipelines.config import ROOT


def main() -> None:
    config = {
        field: os.environ.get(f"NUXT_PUBLIC_COGNITO_{field}", "")
        for field in ("ISSUER", "CLIENT_ID", "DOMAIN")
    }
    issuer = re.fullmatch(
        r"https://cognito-idp\.([a-z0-9-]+)\.amazonaws\.com/\1_[a-zA-Z0-9]+", config["ISSUER"]
    )
    if (
        issuer is None
        or not re.fullmatch(r"[a-z0-9]{1,128}", config["CLIENT_ID"])
        or not re.fullmatch(
            rf"https://[a-z0-9-]+\.auth\.{issuer[1]}\.amazoncognito\.com", config["DOMAIN"]
        )
    ):
        raise SystemExit("Set the public Cognito issuer, client ID and domain for static hosting")
    subprocess.run(["sh", "scripts/frontend.sh", "exec", "nuxt", "generate"], cwd=ROOT, check=True)
    static = ROOT / "frontend/.output/public"
    for relative in ("index.html", "auth/callback/index.html", "admin/index.html"):
        content = (static / Path(relative)).read_text()
        if any(value not in content for value in config.values()):
            raise SystemExit(f"Cognito public configuration is missing from {relative}")
    print("Public OIDC configuration verified on workspace, callback and administrator pages.")


if __name__ == "__main__":
    main()
