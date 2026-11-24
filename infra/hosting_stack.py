"""Synthesize the standalone hosted UI and API. No deployment is performed here."""

import argparse
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
from aws_cdk import aws_apigateway as gateway
from aws_cdk import aws_cloudfront as edge
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_ecr_assets as assets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as functions
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3

from infra.agentcore_stack import stage_source
from infra.identity_stack import identity_stack
from infra.settings import Settings


def hosting_stack(app: App, settings: Settings, source: Path) -> Stack:
    prefix = settings.project
    stack = Stack(
        app,
        f"{prefix}-hosting",
        env=Environment(account=settings.account, region=settings.region),
        synthesizer=DefaultStackSynthesizer(qualifier=settings.bootstrap_qualifier),
        description="AEGIS private static UI and authenticated regional response-streaming API.",
    )
    for name, value in {"Project": "AEGIS", "Environment": "dev", "AegisScope": prefix}.items():
        Tags.of(stack).add(name, value)

    def parameter(name: str, pattern: str) -> str:
        return CfnParameter(stack, name, type="String", allowed_pattern=pattern).value_as_string

    def arn(service: str, resource: str, resource_name: str | None = None) -> str:
        return stack.format_arn(
            service=service,
            resource=resource,
            resource_name=resource_name,
            arn_format=ArnFormat.SLASH_RESOURCE_NAME,
        )

    lake = parameter("LakeBucket", r"[a-z0-9.-]{3,63}")
    results = parameter("ResultsBucket", r"[a-z0-9.-]{3,63}")
    accounts = parameter("IdentityBucket", r"[a-z0-9.-]{3,63}")
    pool = parameter("CognitoPool", rf"{settings.region}_[A-Za-z0-9]+")
    kms = parameter(
        "LakeKmsArn", rf"arn:aws:kms:{settings.region}:{settings.account}:key/[a-f0-9-]{{36}}"
    )
    snapshot = parameter("PinnedSnapshot", r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
    issuer = parameter(
        "CognitoIssuer",
        rf"https://cognito-idp\.{settings.region}\.amazonaws.com/{settings.region}_[A-Za-z0-9]+",
    )
    audience = parameter("CognitoClient", r"[a-z0-9]{1,128}")
    upstream = parameter(
        "RuntimeUrl",
        rf"https://bedrock-agentcore\.{settings.region}\.amazonaws.com/runtimes/"
        r"[A-Za-z0-9%:_/-]+/invocations\?qualifier=DEFAULT",
    )
    context_digest = CfnParameter(
        stack,
        "NetworkContextDigest",
        type="String",
        default="",
        allowed_pattern=r"(?:[a-f0-9]{64})?",
        description="Optional separately approved and immutable network companion SHA-256.",
    ).value_as_string
    log = logs.LogGroup(
        stack, "ApiLogs", retention=logs.RetentionDays.ONE_WEEK, removal_policy=RemovalPolicy.RETAIN
    )
    role = iam.Role(stack, "ApiRole", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
    log.grant_write(role)
    for actions, resources, conditions in (
        (
            ["s3:GetObject", "s3:PutObject"],
            [f"arn:aws:s3:::{accounts}/identity/accounts/*"],
            {},
        ),
        (["s3:ListBucket"], [f"arn:aws:s3:::{accounts}"], {}),
        (
            [
                "cognito-idp:AdminGetUser",
                "cognito-idp:AdminListGroupsForUser",
                "cognito-idp:ListUsers",
            ],
            [arn("cognito-idp", "userpool", pool)],
            {},
        ),
        (
            ["s3:GetObject"],
            [
                f"arn:aws:s3:::{lake}/control/releases/{snapshot}.json",
                f"arn:aws:s3:::{lake}/snapshots/{snapshot}/manifest.json",
                f"arn:aws:s3:::{lake}/snapshots/{snapshot}/raw/00-cisa.json",
                f"arn:aws:s3:::{lake}/iceberg/*",
                f"arn:aws:s3:::{lake}/control/network/{snapshot}/{context_digest}.json",
            ],
            {},
        ),
        (
            ["s3:GetBucketLocation", "s3:ListBucket"],
            [f"arn:aws:s3:::{lake}", f"arn:aws:s3:::{results}"],
            {},
        ),
        (["s3:GetObject", "s3:PutObject"], [f"arn:aws:s3:::{results}/queries/*"], {}),
        (
            ["kms:Decrypt", "kms:GenerateDataKey"],
            [kms],
            {"StringEquals": {"kms:ViaService": f"s3.{settings.region}.amazonaws.com"}},
        ),
        (
            ["glue:GetDatabase", "glue:GetTable", "glue:GetTableVersion", "glue:GetTableVersions"],
            [
                arn("glue", "catalog"),
                arn("glue", "database", settings.database),
                arn("glue", "table", f"{settings.database}/*"),
            ],
            {},
        ),
        (
            [
                "athena:GetWorkGroup",
                "athena:StartQueryExecution",
                "athena:GetQueryExecution",
                "athena:GetQueryResults",
                "athena:StopQueryExecution",
            ],
            [arn("athena", "workgroup", prefix)],
            {},
        ),
    ):
        role.add_to_policy(
            iam.PolicyStatement(actions=actions, resources=resources, conditions=conditions)
        )

    api = functions.DockerImageFunction(
        stack,
        "Api",
        code=functions.DockerImageCode.from_image_asset(
            str(source),
            file="infra/Hosting.Dockerfile",
            platform=assets.Platform.LINUX_ARM64,
        ),
        architecture=functions.Architecture.ARM_64,
        memory_size=1536,
        timeout=Duration.seconds(70),
        reserved_concurrent_executions=3,
        log_group=log,
        role=role,
        environment={
            "AEGIS_AWS_ACCOUNT": settings.account,
            "AEGIS_AWS_REGION": settings.region,
            "AEGIS_PROJECT_PREFIX": prefix,
            "AEGIS_SNAPSHOT": snapshot,
            "AEGIS_LAKE_BUCKET": lake,
            "AEGIS_IDENTITY_BUCKET": accounts,
            "AEGIS_RESULTS_BUCKET": results,
            "AEGIS_LAKE_KMS_ARN": kms,
            "AEGIS_OIDC_ISSUER": issuer,
            "AEGIS_OIDC_AUDIENCE": audience,
            "AEGIS_RUNTIME_URL": upstream,
            "AEGIS_NETWORK_CONTEXT_DIGEST": context_digest,
        },
    )
    rest = gateway.RestApi(
        stack,
        "RegionalApi",
        endpoint_types=[gateway.EndpointType.REGIONAL],
        cloud_watch_role=False,
        deploy_options=gateway.StageOptions(
            stage_name="pilot",
            throttling_rate_limit=3,
            throttling_burst_limit=6,
            data_trace_enabled=False,
            caching_enabled=False,
        ),
    )
    resource = rest.root.add_resource("api").add_resource("aegis").add_resource("{proxy+}")
    for method in ("GET", "POST"):
        resource.add_method(
            method,
            gateway.LambdaIntegration(
                api,
                allow_test_invoke=False,
                response_transfer_mode=gateway.ResponseTransferMode.STREAM,
                timeout=Duration.seconds(65),
            ),
        )

    bucket = s3.Bucket(
        stack,
        "Ui",
        encryption=s3.BucketEncryption.S3_MANAGED,
        enforce_ssl=True,
        versioned=True,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
        removal_policy=RemovalPolicy.RETAIN,
    )
    callback = edge.Function(
        stack,
        "OidcCallback",
        code=edge.FunctionCode.from_inline(
            "function handler(event) { var request = event.request; "
            "if (request.uri === '/auth/callback' || request.uri === '/auth/callback/') "
            "request.uri = '/auth/callback/index.html'; "
            "if (request.uri === '/admin' || request.uri === '/admin/') "
            "request.uri = '/admin/index.html'; return request; }"
        ),
    )
    response_policy = edge.ResponseHeadersPolicy(
        stack,
        "SecurityHeaders",
        security_headers_behavior=edge.ResponseSecurityHeadersBehavior(
            content_type_options=edge.ResponseHeadersContentTypeOptions(override=True),
            frame_options=edge.ResponseHeadersFrameOptions(
                frame_option=edge.HeadersFrameOption.DENY, override=True
            ),
            strict_transport_security=edge.ResponseHeadersStrictTransportSecurity(
                access_control_max_age=Duration.days(365),
                override=True,
            ),
            referrer_policy=edge.ResponseHeadersReferrerPolicy(
                referrer_policy=edge.HeadersReferrerPolicy.NO_REFERRER,
                override=True,
            ),
        ),
    )
    static = origins.S3BucketOrigin.with_origin_access_control(bucket)
    distribution = edge.Distribution(
        stack,
        "Workspace",
        default_root_object="index.html",
        price_class=edge.PriceClass.PRICE_CLASS_100,
        error_responses=[
            edge.ErrorResponse(http_status=status, ttl=Duration.seconds(0))
            for status in (400, 403, 404, 405, 414, 416, 500, 501, 502, 503, 504)
        ],
        default_behavior=edge.BehaviorOptions(
            origin=static,
            viewer_protocol_policy=edge.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            cache_policy=edge.CachePolicy.CACHING_DISABLED,
            response_headers_policy=response_policy,
            function_associations=[
                edge.FunctionAssociation(
                    event_type=edge.FunctionEventType.VIEWER_REQUEST, function=callback
                ),
            ],
        ),
        additional_behaviors={
            "_nuxt/*": edge.BehaviorOptions(
                origin=static,
                viewer_protocol_policy=edge.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=edge.CachePolicy.CACHING_OPTIMIZED,
                response_headers_policy=response_policy,
            ),
            "api/aegis/*": edge.BehaviorOptions(
                origin=origins.HttpOrigin(
                    f"{rest.rest_api_id}.execute-api.{settings.region}.amazonaws.com",
                    origin_path="/pilot",
                    protocol_policy=edge.OriginProtocolPolicy.HTTPS_ONLY,
                    connection_attempts=1,
                    read_timeout=Duration.seconds(60),
                ),
                allowed_methods=edge.AllowedMethods.ALLOW_ALL,
                viewer_protocol_policy=edge.ViewerProtocolPolicy.HTTPS_ONLY,
                cache_policy=edge.CachePolicy.CACHING_DISABLED,
                origin_request_policy=edge.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                compress=False,
                response_headers_policy=response_policy,
            ),
        },
    )
    CfnOutput(stack, "WorkspaceUrl", value=f"https://{distribution.distribution_domain_name}")
    CfnOutput(stack, "UiBucket", value=bucket.bucket_name)
    CfnOutput(stack, "DistributionId", value=distribution.distribution_id)
    return stack


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="data/hosting-cdk")
    args = parser.parse_args()
    settings = Settings.load(offline=True)
    root = Path(__file__).resolve().parents[1]
    with TemporaryDirectory(prefix="aegis-hosting-") as directory:
        source = Path(directory) / "source"
        stage_source(source)
        (source / "infra" / "Hosting.Dockerfile").write_bytes(
            (root / "infra/Hosting.Dockerfile").read_bytes()
        )
        app = App(outdir=args.out)
        hosting_stack(app, settings, source)
        identity_stack(app, settings)
        app.synth()


if __name__ == "__main__":
    main()
