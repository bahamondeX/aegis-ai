"""Offline-reviewable V2 EPSS canary stack using the existing lake bucket and key."""

import os

from aws_cdk import (
    App,
    CfnOutput,
    CfnParameter,
    DefaultStackSynthesizer,
    Duration,
    Environment,
    IgnoreMode,
    RemovalPolicy,
    Size,
    Stack,
    Tags,
)
from aws_cdk import aws_ecr_assets as ecr_assets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs

from infra.settings import Settings
from pipelines.bronze import PREFIX
from pipelines.config import ROOT


def canary_stack(app: App, settings: Settings, *, historical: bool = False) -> Stack:
    name = f"{settings.project}-v2-epss"
    stack = Stack(
        app,
        name,
        env=Environment(account=settings.account, region=settings.region),
        synthesizer=DefaultStackSynthesizer(qualifier=settings.bootstrap_qualifier),
    )
    for key, value in (
        ("Project", "AEGIS"),
        ("Environment", "dev"),
        ("AegisScope", settings.project),
        ("ReleaseLane", "V2"),
    ):
        Tags.of(stack).add(key, value)
    bucket = CfnParameter(stack, "LakeBucket", allowed_pattern=r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
    kms = CfnParameter(
        stack,
        "LakeKeyArn",
        allowed_pattern=rf"arn:aws:kms:{settings.region}:{settings.account}:key/[a-z0-9-]+",
    )
    plan = CfnParameter(stack, "ApprovedPlanDigest", allowed_pattern=r"[a-f0-9]{64}")
    history = (
        CfnParameter(stack, "ApprovedCampaignDigest", allowed_pattern=r"[a-f0-9]{64}")
        if historical
        else None
    )
    log = logs.LogGroup(
        stack,
        "CanaryLogs",
        log_group_name=f"/aws/lambda/{name}",
        retention=logs.RetentionDays.TWO_WEEKS,
        removal_policy=RemovalPolicy.RETAIN,
    )
    role = iam.Role(stack, "WorkerRole", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
    log.grant_write(role)
    bucket_arn = f"arn:aws:s3:::{bucket.value_as_string}"
    window = "*" if history else plan.value_as_string
    write_prefixes = [
        f"{PREFIX}/epss/raw/*",
        f"{PREFIX}/epss/normalized/*",
        f"{PREFIX}/manifests/epss-dates/*",
        f"{PREFIX}/manifests/epss-jobs/{window}/*",
    ]
    read_prefixes = [*write_prefixes, f"{PREFIX}/manifests/epss-plans/{window}.json"]
    if history:
        read_prefixes.append(f"{PREFIX}/manifests/epss-campaigns/{history.value_as_string}/*")
    role.add_to_policy(
        iam.PolicyStatement(
            actions=["s3:GetObject"],
            resources=[f"{bucket_arn}/{item}" for item in read_prefixes],
        )
    )
    role.add_to_policy(
        iam.PolicyStatement(
            actions=["s3:PutObject"],
            resources=[f"{bucket_arn}/{item}" for item in write_prefixes],
            conditions={
                "StringEquals": {
                    "s3:if-none-match": "*",
                    "s3:x-amz-server-side-encryption": "aws:kms",
                    "s3:x-amz-server-side-encryption-aws-kms-key-id": kms.value_as_string,
                }
            },
        )
    )
    role.add_to_policy(
        iam.PolicyStatement(
            actions=["s3:ListBucket"],
            resources=[bucket_arn],
            conditions={"StringLike": {"s3:prefix": read_prefixes}},
        )
    )
    role.add_to_policy(
        iam.PolicyStatement(
            actions=["kms:Decrypt", "kms:GenerateDataKey"],
            resources=[kms.value_as_string],
            conditions={
                "StringEquals": {"kms:ViaService": f"s3.{settings.region}.amazonaws.com"},
                "StringLike": {
                    "kms:EncryptionContext:aws:s3:arn": [
                        bucket_arn,
                        *[f"{bucket_arn}/{item}" for item in read_prefixes],
                    ]
                },
            },
        )
    )
    worker = lambda_.DockerImageFunction(
        stack,
        "EpssWorker",
        function_name=name,
        architecture=lambda_.Architecture.ARM_64,
        code=lambda_.DockerImageCode.from_image_asset(
            str(ROOT),
            file="infra/Dockerfile",
            platform=ecr_assets.Platform.LINUX_ARM64,
            ignore_mode=IgnoreMode.DOCKER,
            cmd=["pipelines.epss_bronze.handler"],
        ),
        timeout=Duration.seconds(120),
        memory_size=1024,
        ephemeral_storage_size=Size.gibibytes(2),
        reserved_concurrent_executions=4 if history else 1,
        retry_attempts=0,
        max_event_age=Duration.minutes(2),
        role=role,
        log_group=log,
        environment={
            "AEGIS_V2_ACCOUNT": settings.account,
            "AEGIS_V2_BUCKET": bucket.value_as_string,
            "AEGIS_V2_KMS": kms.value_as_string,
            "AEGIS_V2_PLAN_ID": plan.value_as_string,
            **({"AEGIS_V2_CAMPAIGN_ID": history.value_as_string} if history else {}),
            "POLARS_MAX_THREADS": "2",
        },
    )
    CfnOutput(stack, "WorkerName", value=worker.function_name)
    return stack


if __name__ == "__main__":
    app = App()
    canary_stack(
        app,
        Settings.load(offline=os.getenv("AEGIS_CDK_OFFLINE") == "1"),
        historical=os.getenv("AEGIS_CDK_V2_HISTORY") == "1",
    )
    app.synth()
