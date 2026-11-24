"""Deploy the approved hosting stack and publish its public static artifact."""

import argparse
import json
import mimetypes
import os
import re
import subprocess
from hashlib import sha256
from pathlib import Path
from urllib.parse import quote

from botocore.exceptions import ClientError

from infra.agent_deploy import existing_stack, outputs, publish_image, review_and_deploy
from infra.hosting_preflight import hosting_budget
from infra.settings import SDK_CONFIG, Settings
from pipelines.cloud import SnapshotStore
from pipelines.config import ROOT, configured_snapshot, project_environment
from pipelines.io import DataError

HOSTING_TYPES = {
    "AWS::ApiGateway::Deployment",
    "AWS::ApiGateway::Method",
    "AWS::ApiGateway::Resource",
    "AWS::ApiGateway::RestApi",
    "AWS::ApiGateway::Stage",
    "AWS::CloudFront::Distribution",
    "AWS::CloudFront::Function",
    "AWS::CloudFront::OriginAccessControl",
    "AWS::CloudFront::ResponseHeadersPolicy",
    "AWS::IAM::Policy",
    "AWS::IAM::Role",
    "AWS::Lambda::Function",
    "AWS::Lambda::Permission",
    "AWS::Logs::LogGroup",
    "AWS::S3::Bucket",
    "AWS::S3::BucketPolicy",
    "AWS::CDK::Metadata",
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("review", "deploy", "google-mapping", "publish-ui"))
    args = parser.parse_args()
    env = project_environment()
    settings = Settings.load(environment=env)
    if hosting_budget(settings, env) < 1:
        raise DataError("the hosting reservation must cover USD 1 for rollout and pilot usage")
    session, _ = settings.identity()
    cfn = session.client("cloudformation", config=SDK_CONFIG)
    prefix = settings.project
    name = f"{prefix}-hosting"
    owned: dict[str, dict[str, str]] = {}
    for label, stack_name in (
        ("lake", settings.stack),
        ("agent", f"{prefix}-agent"),
        ("identity", f"{prefix}-identity"),
        ("bootstrap", settings.bootstrap_stack),
    ):
        stack = existing_stack(cfn, stack_name, settings)
        if stack is None:
            raise DataError(f"missing owned {label} stack")
        owned[label] = outputs(stack)
    current = existing_stack(cfn, name, settings, accept_empty_review=True)
    identity = owned["identity"]
    client = session.client("cognito-idp", config=SDK_CONFIG)
    pool, client_id, login = (identity[key] for key in ("PoolId", "BrowserClientId", "LoginDomain"))
    issuer = f"https://cognito-idp.{settings.region}.amazonaws.com/{pool}"
    domain = f"https://{login}.auth.{settings.region}.amazoncognito.com"
    s3 = session.client("s3", config=SDK_CONFIG)
    if args.operation == "google-mapping":
        item = client.describe_identity_provider(UserPoolId=pool, ProviderName="Google")[
            "IdentityProvider"
        ]
        details = item["ProviderDetails"]
        if not details.get("client_secret") or not details.get("client_id"):
            raise DataError("the Google identity provider credentials are unavailable")
        scopes = details.get("authorize_scopes", "").split()
        if not {"openid", "email", "profile"} <= set(scopes):
            raise DataError("the existing Google provider needs openid, email and profile scopes")
        mapping = {**item["AttributeMapping"], "email": "email", "email_verified": "email_verified"}
        if mapping != item["AttributeMapping"]:
            client.update_identity_provider(
                UserPoolId=pool,
                ProviderName="Google",
                AttributeMapping=mapping,
                ProviderDetails={
                    k: details[k] for k in ("client_id", "client_secret", "authorize_scopes")
                },
            )
        print("Google attribute mapping checked without changing credentials.")
        return
    if args.operation == "publish-ui":
        if current is None:
            raise DataError("hosting stack is missing")
        hosting = outputs(current)
        configured = client.describe_user_pool_client(UserPoolId=pool, ClientId=client_id)[
            "UserPoolClient"
        ]
        if hosting["WorkspaceUrl"] + "/auth/callback" not in configured["CallbackURLs"]:
            raise DataError("the hosted callback is missing from the approved browser client")
        subprocess.run(
            ["make", "build-ui-static"],
            cwd=ROOT,
            check=True,
            timeout=240,
            env={
                **os.environ,
                "NUXT_PUBLIC_COGNITO_ISSUER": issuer,
                "NUXT_PUBLIC_COGNITO_CLIENT_ID": client_id,
                "NUXT_PUBLIC_COGNITO_DOMAIN": domain,
                "NUXT_PUBLIC_IDENTITY_APPROVAL": "true",
                "NUXT_PUBLIC_GOOGLE_ENABLED": str(
                    "Google" in configured["SupportedIdentityProviders"]
                ).lower(),
            },
        )
        root = ROOT / "frontend/.output/public"
        files = sorted(path for path in root.rglob("*") if path.is_file())
        if not (1 <= len(files) <= 3000) or sum(p.stat().st_size for p in files) > 100_000_000:
            raise DataError("static artifact exceeds the pilot publication limits")
        for path in files:
            relative = path.relative_to(root).as_posix()
            if (
                any(part.startswith(".") for part in path.relative_to(root).parts)
                or path.suffix == ".map"
            ):
                raise DataError("unexpected private file or source map in static artifact")
            if path.suffix in {".js", ".json", ".html"} and re.search(
                rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
                path.read_bytes(),
            ):
                raise DataError(f"static artifact contains a credential marker in {relative}")
        s3.head_bucket(Bucket=hosting["UiBucket"], ExpectedBucketOwner=settings.account)
        for path in sorted(files, key=lambda f: f.suffix == ".html"):
            relative = path.relative_to(root).as_posix()
            mime = mimetypes.guess_type(relative)[0] or "application/octet-stream"
            if path.suffix == ".js":
                mime = "text/javascript"
            with path.open("rb") as content:
                s3.put_object(
                    Bucket=hosting["UiBucket"],
                    Key=relative,
                    Body=content,
                    ExpectedBucketOwner=settings.account,
                    ContentType=mime,
                    CacheControl="public, max-age=31536000, immutable"
                    if relative.startswith("_nuxt/")
                    else "no-cache",
                )
        print(json.dumps({"url": hosting["WorkspaceUrl"], "objects_published": len(files)}))
        return

    lake, agent = owned["lake"], owned["agent"]
    snapshot = configured_snapshot(env)
    if snapshot is None or not SnapshotStore(s3, lake["LakeBucket"]).release(snapshot):
        raise DataError("the pinned release is missing from the owned lake")
    if not agent["RuntimeArn"].startswith(
        f"arn:aws:bedrock-agentcore:{settings.region}:{settings.account}:runtime/"
    ):
        raise DataError("runtime is outside the approved account")
    directory = Path(env.get("AEGIS_DATA_DIR") or "data") / "network" / str(snapshot)
    companion = (directory / "network-context.json").read_bytes()
    digest = sha256(companion).hexdigest()
    if len(companion) > 64 * 1024 or digest != (directory / "manifest.json").read_text().strip():
        raise DataError("network companion is too large or does not match the reviewed checksum")
    target = f"control/network/{snapshot}/{digest}.json"
    assembly = Path(env.get("AEGIS_DATA_DIR") or "data") / "hosting-cdk"
    parameters = {
        "LakeBucket": lake["LakeBucket"],
        "ResultsBucket": lake["ResultsBucket"],
        "IdentityBucket": agent["CheckpointBucket"],
        "LakeKmsArn": lake["KmsKey"],
        "PinnedSnapshot": str(snapshot),
        "CognitoPool": pool,
        "CognitoIssuer": issuer,
        "CognitoClient": client_id,
        "NetworkContextDigest": digest,
        "RuntimeUrl": (
            f"https://bedrock-agentcore.{settings.region}.amazonaws.com/runtimes/"
            f"{quote(agent['RuntimeArn'], safe='')}/invocations?qualifier=DEFAULT"
        ),
    }
    template = assembly / f"{name}.template.json"
    if args.operation == "deploy":
        publish_image(session, settings, assembly, name)
        try:
            s3.put_object(
                Bucket=lake["LakeBucket"],
                Key=target,
                Body=companion,
                ContentType="application/json",
                ExpectedBucketOwner=settings.account,
                ServerSideEncryption="aws:kms",
                SSEKMSKeyId=lake["KmsKey"],
                IfNoneMatch="*",
                Metadata={"sha256": digest},
            )
        except ClientError as error:
            if error.response["Error"]["Code"] != "PreconditionFailed":
                raise
            present = s3.head_object(
                Bucket=lake["LakeBucket"], Key=target, ExpectedBucketOwner=settings.account
            )
            if (
                present.get("Metadata", {}).get("sha256") != digest
                or present.get("SSEKMSKeyId") != lake["KmsKey"]
            ):
                raise DataError(
                    "the existing companion does not match the reviewed artifact"
                ) from None
    deployed = review_and_deploy(
        cfn,
        name,
        settings,
        template,
        parameters,
        HOSTING_TYPES,
        review_only=args.operation == "review",
        max_changes=40,
    )
    print(json.dumps({"url": deployed.get("WorkspaceUrl"), "network_sha256": digest}))


if __name__ == "__main__":
    main()
