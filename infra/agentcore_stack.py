"""Synthesize the separately scoped AgentCore runtime without publishing AWS assets."""

import argparse
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

from aws_cdk import (
    App,
    ArnFormat,
    CfnOutput,
    CfnParameter,
    DefaultStackSynthesizer,
    Duration,
    Environment,
    RemovalPolicy,
    Stack,
    Tags,
)
from aws_cdk import aws_bedrockagentcore as agentcore
from aws_cdk import aws_ecr_assets as assets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_s3 as s3

from infra.settings import Settings

ROOT = Path(__file__).resolve().parents[1]


def stage_source(destination: Path) -> None:
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store")
    for directory in ("backend", "pipelines", "schemas", "sql"):
        shutil.copytree(ROOT / directory, destination / directory, ignore=ignore)
    for filename in (
        "pyproject.toml",
        "uv.lock",
        "infra/AgentCore.Dockerfile",
        "infra/settings.py",
        "infra/__init__.py",
    ):
        target = destination / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / filename, target)


def agent_stack(app: App, settings: Settings, source: Path) -> Stack:
    prefix = settings.project
    name = prefix.replace("-", "_") + "_investigations"
    stack = Stack(
        app,
        f"{prefix}-agent",
        env=Environment(account=settings.account, region=settings.region),
        synthesizer=DefaultStackSynthesizer(qualifier=settings.bootstrap_qualifier),
        description="Authenticated AEGIS investigation runtime using a pinned lake release.",
    )
    stack.template_options.metadata = {
        "AWSToolsMetrics": {"AWSAgentToolkit": "aws-cloudformation@3"}
    }
    for key, label in {"Project": "AEGIS", "Environment": "dev", "AegisScope": prefix}.items():
        Tags.of(stack).add(key, label)
    scope = f"{stack.account}/{stack.region}/{prefix}"

    def parameter(identifier: str, pattern: str) -> str:
        return CfnParameter(
            stack, identifier, type="String", allowed_pattern=pattern
        ).value_as_string

    lake = s3.Bucket.from_bucket_name(
        stack, "ExistingLake", parameter("LakeBucket", r"[a-z0-9.-]{3,63}")
    )
    results = s3.Bucket.from_bucket_name(
        stack, "ExistingResults", parameter("ResultsBucket", r"[a-z0-9.-]{3,63}")
    )
    key_arn = parameter(
        "LakeKmsArn", rf"arn:aws:kms:{settings.region}:{settings.account}:key/[a-f0-9-]{{36}}"
    )
    key = kms.Key.from_key_arn(stack, "ExistingLakeKey", key_arn)
    snapshot = parameter("PinnedSnapshot", r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
    model_id = parameter("ModelId", r"[a-z][a-z0-9_-]*\.[a-z0-9.:-]{1,100}")
    issuer = parameter("OidcIssuer", r"https://[^/?#]+(?:/[^/?#]+)*")
    jwks = parameter("OidcJwks", r"https://[^?#]+")
    audience = parameter("OidcAudience", r"[A-Za-z0-9:/._-]{1,128}")
    workspace = parameter("OidcWorkspace", r"[A-Za-z0-9._-]{1,64}")
    ceiling_pattern = r"[0-9]+(?:\.[0-9]{1,8})?"
    checkpoints = s3.Bucket(
        stack,
        "Checkpoints",
        encryption=s3.BucketEncryption.KMS,
        encryption_key=key,
        bucket_key_enabled=True,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
        versioned=True,
        enforce_ssl=True,
        removal_policy=RemovalPolicy.RETAIN,
        lifecycle_rules=[
            s3.LifecycleRule(
                expiration=Duration.days(7),
                noncurrent_version_expiration=Duration.days(7),
                prefix="checkpoints/run/",
            ),
            s3.LifecycleRule(expired_object_delete_marker=True, prefix="checkpoints/run/"),
        ],
    )
    bucket_resource = checkpoints.node.default_child
    bucket_resource.add_metadata(
        "com.aws.cloudformation.Context",
        {
            "why": "Durable SSE and inference reservations shared by runtime instances.",
            "must": "Use the existing project KMS key. Expire the run prefix only.",
        },
    )
    image = assets.DockerImageAsset(
        stack,
        "RuntimeImage",
        directory=str(source),
        file="infra/AgentCore.Dockerfile",
        platform=assets.Platform.LINUX_ARM64,
    )

    def arn(service: str, resource: str, resource_name: str | None = None) -> str:
        return stack.format_arn(service=service, resource=resource, resource_name=resource_name)

    wg = arn("athena", "workgroup", prefix)
    log = stack.format_arn(
        service="logs",
        resource="log-group",
        resource_name=f"/aws/bedrock-agentcore/runtimes/{name}-*",
        arn_format=ArnFormat.COLON_RESOURCE_NAME,
    )
    model = f"arn:{stack.partition}:bedrock:{stack.region}::foundation-model/{model_id}"
    policy = iam.PolicyDocument(
        statements=[
            iam.PolicyStatement(actions=["ecr:GetAuthorizationToken"], resources=["*"]),
            iam.PolicyStatement(
                actions=["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
                resources=[image.repository.repository_arn],
            ),
            iam.PolicyStatement(
                actions=[
                    "bedrock:GetFoundationModel",
                    "bedrock:InvokeModel",
                ],
                resources=[model],
            ),
            iam.PolicyStatement(
                actions=["bedrock:GetFoundationModelAvailability"],
                resources=["*"],
                conditions={"StringEquals": {"aws:RequestedRegion": stack.region}},
            ),
            iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[
                    lake.arn_for_objects(f"control/releases/{snapshot}.json"),
                    lake.arn_for_objects(f"snapshots/{snapshot}/manifest.json"),
                    lake.arn_for_objects(f"snapshots/{snapshot}/raw/00-cisa.json"),
                    lake.arn_for_objects("iceberg/*"),
                ],
            ),
            iam.PolicyStatement(
                actions=["s3:GetBucketLocation", "s3:ListBucket"],
                resources=[lake.bucket_arn, results.bucket_arn, checkpoints.bucket_arn],
            ),
            iam.PolicyStatement(
                actions=["s3:GetObject", "s3:PutObject"],
                resources=[
                    results.arn_for_objects("queries/*"),
                    checkpoints.arn_for_objects("checkpoints/*"),
                ],
            ),
            iam.PolicyStatement(
                actions=["kms:Decrypt", "kms:GenerateDataKey"],
                resources=[key_arn],
                conditions={
                    "StringEquals": {"kms:ViaService": f"s3.{stack.region}.{stack.url_suffix}"}
                },
            ),
            iam.PolicyStatement(
                actions=[
                    "glue:GetDatabase",
                    "glue:GetTable",
                    "glue:GetTableVersion",
                    "glue:GetTableVersions",
                ],
                resources=[
                    arn("glue", "catalog"),
                    arn("glue", "database", settings.database),
                    arn("glue", "table", f"{settings.database}/*"),
                ],
            ),
            iam.PolicyStatement(
                actions=[
                    "athena:GetWorkGroup",
                    "athena:StartQueryExecution",
                    "athena:GetQueryExecution",
                    "athena:GetQueryResults",
                    "athena:StopQueryExecution",
                ],
                resources=[wg],
            ),
            iam.PolicyStatement(
                actions=[
                    "logs:CreateLogGroup",
                    "logs:DescribeLogStreams",
                    "logs:PutResourcePolicy",
                ],
                resources=[log, f"{log}:*"],
            ),
            iam.PolicyStatement(
                actions=["logs:DescribeLogGroups"],
                resources=[
                    stack.format_arn(
                        service="logs",
                        resource="log-group",
                        resource_name="*",
                        arn_format=ArnFormat.COLON_RESOURCE_NAME,
                    )
                ],
            ),
            iam.PolicyStatement(
                actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                resources=[f"{log}:log-stream:*"],
            ),
        ],
    )
    role = iam.Role(
        stack,
        "RuntimeRole",
        assumed_by=iam.ServicePrincipal(
            "bedrock-agentcore.amazonaws.com",
            conditions={
                "StringEquals": {"aws:SourceAccount": stack.account},
                "ArnLike": {"aws:SourceArn": arn("bedrock-agentcore", "runtime", f"{name}-*")},
            },
        ),
        inline_policies={"AegisRuntimeAccess": policy},
    )
    role.node.default_child.add_metadata(
        "com.aws.cloudformation.Context",
        {
            "why": "A dedicated service role limits the runtime to the read-only evidence scope.",
            "must": "Scope trust to this runtime and inference to its configured model ARN.",
        },
    )
    runtime = agentcore.CfnRuntime(
        stack,
        "Runtime",
        agent_runtime_name=name,
        role_arn=role.role_arn,
        agent_runtime_artifact=agentcore.CfnRuntime.AgentRuntimeArtifactProperty(
            container_configuration=agentcore.CfnRuntime.ContainerConfigurationProperty(
                container_uri=image.image_uri
            ),
        ),
        protocol_configuration="HTTP",
        network_configuration=agentcore.CfnRuntime.NetworkConfigurationProperty(
            network_mode="PUBLIC"
        ),
        authorizer_configuration=agentcore.CfnRuntime.AuthorizerConfigurationProperty(
            custom_jwt_authorizer=agentcore.CfnRuntime.CustomJWTAuthorizerConfigurationProperty(
                discovery_url=f"{issuer}/.well-known/openid-configuration",
                allowed_clients=[audience],
            ),
        ),
        request_header_configuration=agentcore.CfnRuntime.RequestHeaderConfigurationProperty(
            request_header_allowlist=["Authorization", "Idempotency-Key", "Last-Event-ID"],
        ),
        lifecycle_configuration=agentcore.CfnRuntime.LifecycleConfigurationProperty(
            idle_runtime_session_timeout=60,
            max_lifetime=120,
        ),
        environment_variables={
            "AEGIS_AWS_ACCOUNT": stack.account,
            "AEGIS_AWS_REGION": stack.region,
            "AEGIS_PROJECT_PREFIX": prefix,
            "AEGIS_AGENTCORE_APPROVAL": parameter("AgentCoreApproval", scope + "/agentcore"),
            "AEGIS_AGENTCORE_BUDGET_USD": parameter("AgentCoreBudgetUsd", ceiling_pattern),
            "AEGIS_BEDROCK_APPROVAL": parameter("BedrockApproval", scope + "/bedrock"),
            "AEGIS_BEDROCK_BUDGET_USD": parameter("BedrockRuntimeBudgetUsd", ceiling_pattern),
            "AEGIS_BEDROCK_INPUT_USD_PER_MILLION": parameter(
                "BedrockInputUsdPerMillion", ceiling_pattern
            ),
            "AEGIS_BEDROCK_OUTPUT_USD_PER_MILLION": parameter(
                "BedrockOutputUsdPerMillion", ceiling_pattern
            ),
            "BEDROCK_MODEL_ID": model_id,
            "AEGIS_LAKE_BUCKET": lake.bucket_name,
            "AEGIS_RESULTS_BUCKET": results.bucket_name,
            "AEGIS_LAKE_KMS_ARN": key_arn,
            "AEGIS_CHECKPOINT_BUCKET": checkpoints.bucket_name,
            "AEGIS_SNAPSHOT": snapshot,
            "AEGIS_OIDC_ISSUER": issuer,
            "AEGIS_OIDC_AUDIENCE": audience,
            "AEGIS_OIDC_WORKSPACE": workspace,
            "AEGIS_OIDC_JWKS": jwks,
        },
    )
    runtime.add_metadata(
        "com.aws.cloudformation.Context",
        {
            "why": "The ARM64 HTTP entrypoint serves SSE with the API's existing JWT contract.",
            "must": "Keep JWT enforcement, release pinning and distinct spending approvals.",
        },
    )
    CfnOutput(stack, "RuntimeArn", value=runtime.attr_agent_runtime_arn)
    CfnOutput(stack, "RuntimeId", value=runtime.attr_agent_runtime_id)
    CfnOutput(stack, "CheckpointBucket", value=checkpoints.bucket_name)
    return stack


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outdir", default="data/agentcore-cdk.out")
    args = parser.parse_args()
    app = App(outdir=args.outdir)
    with TemporaryDirectory(prefix="aegis-agentcore-") as directory:
        source = Path(directory)
        stage_source(source)
        agent_stack(app, Settings.load(offline=True), source)
        app.synth()


if __name__ == "__main__":
    main()
