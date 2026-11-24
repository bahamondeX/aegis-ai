"""Run bounded Chromium checks against the actual owned CloudFront distribution."""

import argparse
import os
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from infra.agent_deploy import existing_stack, outputs
from infra.hosting_preflight import hosting_budget
from infra.settings import SDK_CONFIG, Settings
from pipelines.config import ROOT, project_environment
from pipelines.io import DataError


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--public-only", action="store_true")
    scope.add_argument("--journey-only", action="store_true")
    scope.add_argument("--session-only", action="store_true")
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    env = project_environment()
    settings = Settings.load(environment=env)
    hosting_budget(settings, env)
    session, _ = settings.identity()
    client = session.client("cloudformation", config=SDK_CONFIG)
    stack = existing_stack(client, f"{settings.project}-hosting", settings)
    if stack is None:
        raise DataError("the owned CloudFront stack is missing")
    url = outputs(stack)["WorkspaceUrl"]
    target = urlsplit(url)
    if (
        target.scheme != "https"
        or not target.hostname
        or not target.hostname.endswith(".cloudfront.net")
    ):
        raise DataError("expected the assigned CloudFront HTTPS origin")
    data = Path(env.get("AEGIS_DATA_DIR") or "data").resolve()
    evidence = args.evidence_dir.resolve() if args.evidence_dir else data / "evidence/final"
    evidence.mkdir(parents=True, exist_ok=True)
    browser_env = {**os.environ, "AEGIS_BROWSER_URL": url, "AEGIS_BROWSER_EVIDENCE": str(evidence)}
    browser_env.pop("AEGIS_BROWSER_HOSTED_FIXTURE", None)
    browser_env.pop("AEGIS_BROWSER_PUBLIC_ONLY", None)

    def fixture(action: str) -> None:
        subprocess.run(
            [
                "uv",
                "run",
                "--locked",
                "--no-sync",
                "python",
                "-m",
                "scripts.agent_identity_fixture",
                action,
                "--hosted",
            ],
            cwd=ROOT,
            check=True,
            timeout=90,
        )

    command = ["sh", "scripts/frontend.sh", "browser", "hosted_acceptance.spec.ts"]
    if args.public_only:
        browser_env["AEGIS_BROWSER_PUBLIC_ONLY"] = "1"
        subprocess.run(
            [*command, "-g", "serves HTTPS"], env=browser_env, cwd=ROOT, check=True, timeout=80
        )
        return
    try:
        fixture("create")
        browser_env["AEGIS_BROWSER_HOSTED_FIXTURE"] = str(
            data / "evidence/agentcore/private/hosted-fixture.json"
        )
        if args.journey_only:
            command.extend(["-g", "approved browser reads"])
        elif args.session_only:
            command.extend(["-g", "hosted cancellation"])
        subprocess.run(command, env=browser_env, cwd=ROOT, check=True, timeout=480)
    finally:
        fixture("disable")


if __name__ == "__main__":
    main()
