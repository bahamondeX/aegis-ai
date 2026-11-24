"""Guard, review and deploy only the AEGIS identity and AgentCore stacks."""

import argparse
import base64
import json
import os
import subprocess
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from typing import Any
from uuid import uuid4

import boto3
from aws_cdk import App
from botocore.client import BaseClient
from botocore.exceptions import ClientError

from backend.investigations.bedrock import bedrock_allocations, model_available, read_amount
from backend.investigations.store import SQLiteStore
from infra.agentcore_stack import agent_stack, stage_source
from infra.identity_stack import identity_stack
from infra.operations import stack_outputs
from infra.settings import SDK_CONFIG, Settings
from pipelines.cloud import SnapshotStore
from pipelines.config import configured_snapshot, project_environment
from pipelines.io import DataError

IDENTITY_TYPES = {
    "AWS::Cognito::UserPool",
    "AWS::Cognito::UserPoolClient",
    "AWS::Cognito::UserPoolGroup",
    "AWS::Cognito::UserPoolDomain",
    "AWS::Lambda::Function",
    "AWS::Lambda::Permission",
    "AWS::Logs::LogGroup",
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::CDK::Metadata",
}
RUNTIME_TYPES = {
    "AWS::BedrockAgentCore::Runtime",
    "AWS::S3::Bucket",
    "AWS::S3::BucketPolicy",
    "AWS::IAM::Role",
    "AWS::CDK::Metadata",
}
AGENT_VALIDATION_ESTIMATE = Decimal("0.60")
LAKE_SCENARIO_WITH_RUNTIME = Decimal("5.70")


def tags(settings: Settings) -> dict[str, str]:
    return {"Project": "AEGIS", "Environment": "dev", "AegisScope": settings.project}


def existing_stack(
    client: BaseClient, name: str, settings: Settings, *, accept_empty_review: bool = False
) -> dict[str, Any] | None:
    try:
        stack = client.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as error:
        detail = error.response["Error"]
        if detail["Code"] == "ValidationError" and "does not exist" in detail["Message"]:
            return None
        raise
    if (
        accept_empty_review
        and name == f"{settings.project}-hosting"
        and stack["StackStatus"] == "REVIEW_IN_PROGRESS"
        and stack["StackId"].startswith(
            f"arn:aws:cloudformation:{settings.region}:{settings.account}:stack/{name}/"
        )
    ):
        resources = client.list_stack_resources(StackName=stack["StackId"])
        changes = client.list_change_sets(StackName=stack["StackId"])
        if not resources["StackResourceSummaries"] and not changes["Summaries"]:
            return None
    labels = {item["Key"]: item["Value"] for item in stack.get("Tags", [])}
    if not tags(settings).items() <= labels.items():
        raise DataError(f"{name} ownership tags differ")
    if stack["StackStatus"] not in {
        "CREATE_COMPLETE",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
    }:
        raise DataError(f"{name} is in {stack['StackStatus']}")
    return stack


def outputs(stack: dict[str, Any]) -> dict[str, str]:
    return {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}


def review_and_deploy(
    client: BaseClient,
    name: str,
    settings: Settings,
    template: Path,
    parameters: dict[str, str],
    types: set[str],
    *,
    review_only: bool = False,
    max_changes: int = 12,
) -> dict[str, str]:
    current = existing_stack(
        client, name, settings, accept_empty_review=name == f"{settings.project}-hosting"
    )
    change = client.create_change_set(
        StackName=name,
        ChangeSetName=f"aegis-{uuid4().hex[:14]}",
        ChangeSetType="UPDATE" if current else "CREATE",
        TemplateBody=template.read_text(),
        Parameters=[
            {"ParameterKey": key, "ParameterValue": value} for key, value in parameters.items()
        ],
        Tags=[{"Key": key, "Value": value} for key, value in tags(settings).items()],
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )["Id"]
    deadline = monotonic() + 120
    while monotonic() < deadline:
        reviewed = client.describe_change_set(ChangeSetName=change)
        if reviewed["Status"] in {"CREATE_COMPLETE", "FAILED", "DELETE_COMPLETE"}:
            break
        sleep(3)
    else:
        raise DataError(f"{name} change-set review exceeded 120 seconds")
    if reviewed["Status"] != "CREATE_COMPLETE":
        reason = reviewed.get("StatusReason", "")
        if current and ("didn't contain changes" in reason or "No updates" in reason):
            client.delete_change_set(ChangeSetName=change)
            print(json.dumps({"stack": name, "change": "unchanged"}), flush=True)
            return outputs(current)
        raise DataError(f"change set failed for {name}: {reason}")
    changes = [item["ResourceChange"] for item in reviewed["Changes"]]
    print(json.dumps({"stack": name, "changes": changes}, default=str), flush=True)
    api_in_place = name == f"{settings.project}-hosting" and any(
        item["LogicalResourceId"] == "ApiF70053CD" and item.get("Replacement") == "False"
        for item in changes
    )

    def replaces_resource(item: dict[str, Any]) -> bool:
        if item.get("Replacement") not in {"True", "Conditional"}:
            return False
        # CloudFormation traces the unchanged Lambda ARN into invoke permissions.
        details = item.get("Details", [])
        return not (
            api_in_place
            and item["ResourceType"] == "AWS::Lambda::Permission"
            and item["Replacement"] == "Conditional"
            and len(details) == 1
            and details[0].get("ChangeSource") == "ResourceAttribute"
            and details[0].get("CausingEntity") == "ApiF70053CD.Arn"
            and details[0]["Target"].get("Name") == "FunctionName"
        )

    if (
        not changes
        or len(changes) > max_changes
        or reviewed.get("NextToken")
        or any(
            item["ResourceType"] not in types
            or item["Action"] not in {"Add", "Modify"}
            or replaces_resource(item)
            for item in changes
        )
    ):
        client.delete_change_set(ChangeSetName=change)
        raise DataError("change set expands the approved project scope or replaces a resource")
    if review_only:
        client.delete_change_set(ChangeSetName=change)
        return outputs(current) if current else {}
    client.execute_change_set(ChangeSetName=change)
    deadline = monotonic() + 780
    while monotonic() < deadline:
        stack = client.describe_stacks(StackName=name)["Stacks"][0]
        status = stack["StackStatus"]
        if status in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
            print(json.dumps({"stack": name, "status": status}), flush=True)
            return outputs(stack)
        if status.endswith(("FAILED", "ROLLBACK_COMPLETE")):
            messages = [
                (item["LogicalResourceId"], item.get("ResourceStatusReason", ""))
                for item in client.describe_stack_events(StackName=name)["StackEvents"][:24]
                if item["ResourceStatus"].endswith("FAILED")
            ]
            raise DataError(f"{name} {status}: {messages}")
        sleep(5)
    raise DataError(f"{name} deployment exceeded 780 seconds")


def publish_image(session: boto3.Session, settings: Settings, assembly: Path, stack: str) -> None:
    manifest = json.loads((assembly / f"{stack}.assets.json").read_text())
    (asset,) = manifest["dockerImages"].values()
    (destination,) = asset["destinations"].values()
    source = asset["source"]
    registry = f"{settings.account}.dkr.ecr.{settings.region}.amazonaws.com"
    repo = (
        f"cdk-{settings.bootstrap_qualifier}-container-assets-{settings.account}-{settings.region}"
    )
    if destination["repositoryName"] != repo or source["platform"] != "linux/arm64":
        raise DataError("synthesized image diverges from the approved bootstrap repository")
    client = session.client("ecr", config=SDK_CONFIG)
    repository = client.describe_repositories(repositoryNames=[repo])["repositories"][0]
    if repository["repositoryUri"] != f"{registry}/{repo}":
        raise DataError("ECR repository is outside the selected account and region")
    label = destination["imageTag"]
    try:
        client.describe_images(repositoryName=repo, imageIds=[{"imageTag": label}])
    except client.exceptions.ImageNotFoundException:
        pass
    else:
        print(json.dumps({"image": "already present", "tag": label}), flush=True)
        return
    folder = assembly / source["directory"]
    target = f"{registry}/{repo}:{label}"
    endpoint = (
        os.environ.get("DOCKER_HOST")
        or subprocess.check_output(
            ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
            text=True,
        ).strip()
    )
    if not endpoint.startswith("unix://"):
        raise DataError("expected a local Docker socket")
    plugin = subprocess.check_output(
        [
            "docker",
            "info",
            "--format",
            '{{range .ClientInfo.Plugins}}{{if eq .Name "buildx"}}{{.Path}}{{end}}{{end}}',
        ],
        text=True,
        timeout=10,
    ).strip()
    with TemporaryDirectory(prefix="aegis-ecr-") as directory:
        env = {**os.environ, "DOCKER_CONFIG": directory, "DOCKER_HOST": endpoint}
        env.pop("DOCKER_CONTEXT", None)
        env.pop("BUILDX_BUILDER", None)
        if plugin and Path(plugin).is_file():
            plugins = Path(directory) / "cli-plugins"
            plugins.mkdir()
            (plugins / "docker-buildx").symlink_to(Path(plugin).resolve())
        subprocess.run(
            [
                "docker",
                "build",
                "--platform",
                "linux/arm64",
                "--provenance=false",
                "-f",
                str(folder / source["dockerFile"]),
                "-t",
                target,
                str(folder),
            ],
            check=True,
            env=env,
            timeout=240,
        )
        (access,) = client.get_authorization_token(registryIds=[settings.account])[
            "authorizationData"
        ]
        if access["proxyEndpoint"] != f"https://{registry}":
            raise DataError("ECR registry endpoint differs from the verified repository")
        username, secret = base64.b64decode(access["authorizationToken"]).split(b":", 1)
        if username != b"AWS":
            raise DataError("expected AWS registry credentials")
        subprocess.run(
            ["docker", "login", "--username", "AWS", "--password-stdin", registry],
            input=secret + b"\n",
            check=True,
            env=env,
            timeout=30,
        )
        subprocess.run(["docker", "push", target], check=True, env=env, timeout=480)
    digest = client.describe_images(repositoryName=repo, imageIds=[{"imageTag": label}])[
        "imageDetails"
    ][0]["imageDigest"]
    print(json.dumps({"image_digest": digest, "tag": label}), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=("identity", "runtime"))
    parser.add_argument("--hosted-origin")
    parser.add_argument("--enable-google", action="store_true")
    parser.add_argument("--review-only", action="store_true")
    args = parser.parse_args()
    environment = project_environment()
    settings = Settings.load(environment=environment)
    scope = f"{settings.account}/{settings.region}/{settings.project}"
    if environment.get("AEGIS_AGENTCORE_APPROVAL") != f"{scope}/agentcore":
        raise DataError("explicit AgentCore approval must match the configured account and region")
    if environment.get("AEGIS_BEDROCK_APPROVAL") != f"{scope}/bedrock":
        raise DataError("explicit Bedrock scope approval is required")
    if read_amount(environment, "AEGIS_AGENTCORE_BUDGET_USD") < AGENT_VALIDATION_ESTIMATE:
        raise DataError("AgentCore validation estimate exceeds the approved ceiling")
    if settings.authorize() < LAKE_SCENARIO_WITH_RUNTIME:
        raise DataError("existing G2 budget cannot cover the bounded runtime verification")
    local, runtime = bedrock_allocations(environment)
    root = Path(environment.get("AEGIS_DATA_DIR") or "data").resolve()
    prior = SQLiteStore(root / "investigations.sqlite3").get("bedrock-spend")
    used = Decimal(json.loads(prior.data)["reserved_usd"]) if prior else Decimal(0)
    if used > local:
        raise DataError("local model reservations already exceed their allocation")
    session, _ = settings.identity()
    cfn = session.client("cloudformation", config=SDK_CONFIG)
    print(
        json.dumps(
            {
                "account_suffix": settings.account[-4:],
                "region": settings.region,
                "local_reserved_usd": str(used),
                "runtime_allocation_usd": str(runtime),
            }
        ),
        flush=True,
    )
    identity_name = f"{settings.project}-identity"
    if args.service == "identity":
        from infra.hosting_preflight import hosting_budget

        hosting_budget(settings, environment)
        if args.hosted_origin is None and not args.review_only:
            raise DataError("provide the CloudFront origin of the owned hosting stack")
        if args.hosted_origin:
            hosting = existing_stack(cfn, f"{settings.project}-hosting", settings)
            if hosting is None or outputs(hosting)["WorkspaceUrl"] != args.hosted_origin:
                raise DataError("the origin does not match the owned hosting stack")
        current_identity = existing_stack(cfn, identity_name, settings)
        if current_identity is None:
            raise DataError("the identity extension requires the existing owned pool")
        assembly = root / "identity-cdk.out"
        app = App(outdir=str(assembly))
        identity_stack(app, settings)
        app.synth()
        identity = review_and_deploy(
            cfn,
            identity_name,
            settings,
            assembly / f"{identity_name}.template.json",
            {
                "ExistingPoolId": outputs(current_identity)["PoolId"],
                "HostedOrigin": args.hosted_origin or "",
                "EnableGoogle": "yes" if args.enable_google else "no",
            },
            IDENTITY_TYPES,
            review_only=args.review_only,
        )
        print(json.dumps({"identity_outputs": sorted(identity)}), flush=True)
        return

    identity_state = existing_stack(cfn, identity_name, settings)
    if identity_state is None:
        raise DataError("deploy the authorized identity stack before runtime publication")
    identity = outputs(identity_state)
    if existing_stack(cfn, settings.bootstrap_stack, settings) is None:
        raise DataError("project bootstrap stack is missing")
    lake = stack_outputs(session, settings)
    snapshot = configured_snapshot(environment)
    store = SnapshotStore(session.client("s3", config=SDK_CONFIG), lake["LakeBucket"])
    if not snapshot or not store.release(snapshot):
        raise DataError("the configured release is missing from the authorized lake")
    model = environment["BEDROCK_MODEL_ID"]
    model_available(session, model)
    issuer = f"https://cognito-idp.{settings.region}.amazonaws.com/{identity['PoolId']}"
    name = f"{settings.project}-agent"
    existing_stack(cfn, name, settings)
    assembly = root / "agentcore-cdk.out"
    app = App(outdir=str(assembly))
    with TemporaryDirectory(prefix="aegis-agentcore-") as directory:
        source = Path(directory)
        stage_source(source)
        agent_stack(app, settings, source)
        app.synth()
    bootstrap = session.client("ssm", config=SDK_CONFIG).get_parameter(
        Name=f"/cdk-bootstrap/{settings.bootstrap_qualifier}/version"
    )["Parameter"]["Value"]
    if not bootstrap.isdecimal() or int(bootstrap) < 6:
        raise DataError("project bootstrap version is missing or does not support assets")
    if not args.review_only:
        publish_image(session, settings, assembly, name)
    deployed = review_and_deploy(
        cfn,
        name,
        settings,
        assembly / f"{name}.template.json",
        {
            "LakeBucket": lake["LakeBucket"],
            "ResultsBucket": lake["ResultsBucket"],
            "LakeKmsArn": lake["KmsKey"],
            "PinnedSnapshot": str(snapshot),
            "ModelId": model,
            "OidcIssuer": issuer,
            "OidcJwks": f"{issuer}/.well-known/jwks.json",
            "OidcAudience": identity["BrowserClientId"],
            "CognitoPool": identity["PoolId"],
            "OidcWorkspace": settings.project,
            "AgentCoreApproval": f"{scope}/agentcore",
            "AgentCoreBudgetUsd": environment["AEGIS_AGENTCORE_BUDGET_USD"],
            "BedrockApproval": f"{scope}/bedrock",
            "BedrockRuntimeBudgetUsd": str(runtime),
            "BedrockInputUsdPerMillion": environment["AEGIS_BEDROCK_INPUT_USD_PER_MILLION"],
            "BedrockOutputUsdPerMillion": environment["AEGIS_BEDROCK_OUTPUT_USD_PER_MILLION"],
        },
        RUNTIME_TYPES,
        review_only=args.review_only,
    )
    if args.review_only:
        return
    runtime_id = deployed["RuntimeId"]
    if not runtime_id.startswith(f"{settings.project.replace('-', '_')}_investigations-"):
        raise DataError("created runtime ID does not match the scoped resource")
    group = f"/aws/bedrock-agentcore/runtimes/{runtime_id}-DEFAULT"
    logs = session.client("logs", config=SDK_CONFIG)
    try:
        logs.create_log_group(logGroupName=group, tags=tags(settings))
    except logs.exceptions.ResourceAlreadyExistsException:
        pass
    logs.put_retention_policy(logGroupName=group, retentionInDays=7)
    (log_group,) = [
        item
        for item in logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        if item["logGroupName"] == group
    ]
    if log_group.get("retentionInDays") != 7:
        raise DataError("runtime log retention verification failed")
    print(json.dumps({"runtime_log_retention_days": log_group["retentionInDays"]}), flush=True)
    print(json.dumps({"runtime_outputs": sorted(deployed)}), flush=True)


if __name__ == "__main__":
    main()
