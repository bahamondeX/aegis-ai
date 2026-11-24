"""Create and disable short-lived users in the scoped AEGIS validation pool."""

import argparse
import json
import os
import secrets
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

from backend.identity import Decision, Status, attributes
from backend.investigations.store import S3Store
from infra.hosting_preflight import hosting_budget
from infra.settings import SDK_CONFIG, Settings
from pipelines.config import configured_snapshot, project_environment
from pipelines.io import DataError


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create", "disable"))
    parser.add_argument("--hosted", action="store_true")
    args = parser.parse_args()
    env = project_environment()
    settings = Settings.load(environment=env)
    scope = f"{settings.account}/{settings.region}/{settings.project}"
    if env.get("AEGIS_AGENTCORE_APPROVAL") != f"{scope}/agentcore":
        raise DataError("scoped AgentCore approval is required")
    if args.hosted:
        hosting_budget(settings, env)
    session, _ = settings.identity()
    cfn = session.client("cloudformation", config=SDK_CONFIG)

    def project_outputs(suffix: str) -> dict[str, str]:
        stack = cfn.describe_stacks(StackName=f"{settings.project}-{suffix}")["Stacks"][0]
        tags = {row["Key"]: row["Value"] for row in stack["Tags"]}
        if tags.get("Project") != "AEGIS" or tags.get("AegisScope") != settings.project:
            raise DataError("stack ownership does not match validation scope")
        return {row["OutputKey"]: row["OutputValue"] for row in stack["Outputs"]}

    identity = project_outputs("identity")
    runtime = project_outputs("agent")
    pool = identity["PoolId"]
    client = session.client("cognito-idp", config=SDK_CONFIG)
    user_pool = client.describe_user_pool(UserPoolId=pool)["UserPool"]
    if (
        user_pool["Name"] != f"{settings.project}-operators"
        or user_pool["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"] == args.hosted
    ):
        raise DataError("the dedicated pool does not match the chosen validation mode")
    root = Path(env.get("AEGIS_DATA_DIR") or "data").resolve()
    folder = root / "evidence/agentcore/private"
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = folder / ("hosted-fixture.json" if args.hosted else "fixture.json")
    if args.action == "disable":
        if not path.exists():
            return
        fixture = json.loads(path.read_text())
        if fixture["pool"] != pool:
            raise DataError("fixture pool differs from the current stack")
        for entry in fixture["users"].values():
            username = entry["username"]
            if not username.startswith("aegis-validation-"):
                raise DataError("fixture user prefix differs")
            client.admin_disable_user(UserPoolId=pool, Username=username)
        path.unlink()
        print(json.dumps({"disabled_users": len(fixture["users"])}))
        return
    if path.exists():
        print("Scoped validation fixture already exists")
        return
    accounts = None
    if args.hosted:
        lake = project_outputs("lake")
        accounts = S3Store(
            session.client("s3", config=SDK_CONFIG),
            runtime["CheckpointBucket"],
            settings.account,
            lake["KmsKey"],
            namespace="identity/accounts",
        )
    users: dict[str, dict[str, str]] = {}
    try:
        for role in ("member", "peer", "foreign"):
            username = f"aegis-validation-{role}-{secrets.token_hex(4)}"
            password = secrets.token_urlsafe(32) + "Aa#1"
            client.admin_create_user(
                UserPoolId=pool,
                Username=username,
                TemporaryPassword=password,
                MessageAction="SUPPRESS",
                **(
                    {
                        "UserAttributes": [
                            {"Name": "email", "Value": username + "@example.invalid"},
                            {"Name": "email_verified", "Value": "true"},
                        ]
                    }
                    if args.hosted
                    else {}
                ),
            )
            users[role] = {"username": username, "password": password}
            client.admin_set_user_password(
                UserPoolId=pool, Username=username, Password=password, Permanent=True
            )
            if role != "foreign" and accounts is not None:
                user = client.admin_get_user(UserPoolId=pool, Username=username)
                subject = UUID(attributes(user)["sub"])
                if not accounts.put(
                    str(subject), Decision(status=Status.APPROVED).model_dump_json().encode(), None
                ):
                    raise DataError("an approved validation subject already has a decision")
            elif role != "foreign":
                client.admin_add_user_to_group(
                    UserPoolId=pool, Username=username, GroupName=settings.project
                )
        record = {
            "hosted": args.hosted,
            "pool": pool,
            "client": identity["BrowserClientId"],
            "domain": (
                f"https://{identity['LoginDomain']}.auth.{settings.region}.amazoncognito.com"
            ),
            "issuer": f"https://cognito-idp.{settings.region}.amazonaws.com/{pool}",
            "runtime": (
                f"https://bedrock-agentcore.{settings.region}.amazonaws.com/runtimes/"
                f"{quote(runtime['RuntimeArn'], safe='')}/invocations?qualifier=DEFAULT"
            ),
            "snapshot": str(configured_snapshot(env)),
            "users": users,
        }
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as handle:
            json.dump(record, handle)
    except BaseException:
        for user in users.values():
            client.admin_disable_user(UserPoolId=pool, Username=user["username"])
        raise
    print(json.dumps({"created_validation_users": len(users), "invite_only": not args.hosted}))


if __name__ == "__main__":
    main()
