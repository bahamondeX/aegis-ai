import os
from pathlib import Path

from aws_cdk import (
    App,
    CfnOutput,
    DefaultStackSynthesizer,
    Duration,
    Environment,
    IgnoreMode,
    RemovalPolicy,
    Size,
    Stack,
    Tags,
)
from aws_cdk import (
    aws_athena as athena,
)
from aws_cdk import (
    aws_ecr_assets as ecr_assets,
)
from aws_cdk import (
    aws_glue as glue,
)
from aws_cdk import (
    aws_iam as iam,
)
from aws_cdk import (
    aws_kms as kms,
)
from aws_cdk import (
    aws_lambda as lambda_,
)
from aws_cdk import (
    aws_logs as logs,
)
from aws_cdk import (
    aws_s3 as s3,
)
from aws_cdk import (
    aws_scheduler as scheduler,
)

from infra.settings import LAMBDA_TIMEOUT, SCAN_CUTOFF, SECRET_KEYS, Settings

ROOT = Path(__file__).resolve().parents[1]


def lake_stack(app: App, settings: Settings) -> Stack:
    stack = Stack(
        app,
        settings.stack,
        env=Environment(account=settings.account, region=settings.region),
        synthesizer=DefaultStackSynthesizer(qualifier=settings.bootstrap_qualifier),
    )
    Tags.of(stack).add("Project", "AEGIS")
    Tags.of(stack).add("Environment", "dev")
    Tags.of(stack).add("AegisScope", settings.project)
    prefix = settings.project
    key = kms.Key(
        stack,
        "ProjectKey",
        alias=f"alias/{prefix}-lake",
        enable_key_rotation=True,
        removal_policy=RemovalPolicy.RETAIN,
    )
    bucket_options = {
        "block_public_access": s3.BlockPublicAccess.BLOCK_ALL,
        "bucket_key_enabled": True,
        "encryption": s3.BucketEncryption.KMS,
        "encryption_key": key,
        "enforce_ssl": True,
        "object_ownership": s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
        "removal_policy": RemovalPolicy.RETAIN,
        "versioned": True,
    }
    lake = s3.Bucket(stack, "Lake", **bucket_options)
    results = s3.Bucket(
        stack,
        "Results",
        **bucket_options,
        lifecycle_rules=[
            s3.LifecycleRule(
                expiration=Duration.days(7),
                noncurrent_version_expiration=Duration.days(7),
            )
        ],
    )
    for bucket in (lake, results):
        if bucket.policy is None:
            raise ValueError("required TLS bucket policy was not created")
        bucket.policy.apply_removal_policy(RemovalPolicy.RETAIN)
    db = glue.CfnDatabase(
        stack,
        "Catalog",
        catalog_id=stack.account,
        database_input=glue.CfnDatabase.DatabaseInputProperty(name=settings.database),
    )
    db.apply_removal_policy(RemovalPolicy.RETAIN)
    workgroup = athena.CfnWorkGroup(
        stack,
        "Queries",
        name=prefix,
        state="ENABLED",
        work_group_configuration=athena.CfnWorkGroup.WorkGroupConfigurationProperty(
            bytes_scanned_cutoff_per_query=SCAN_CUTOFF,
            enforce_work_group_configuration=True,
            publish_cloud_watch_metrics_enabled=True,
            engine_version=athena.CfnWorkGroup.EngineVersionProperty(
                selected_engine_version="Athena engine version 3"
            ),
            result_configuration=athena.CfnWorkGroup.ResultConfigurationProperty(
                output_location=f"s3://{results.bucket_name}/queries/",
                expected_bucket_owner=stack.account,
                encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                    encryption_option="SSE_KMS", kms_key=key.key_arn
                ),
            ),
        ),
    )
    log_group = logs.LogGroup(
        stack,
        "IngestLogs",
        log_group_name=f"/aws/lambda/{prefix}-ingest",
        retention=logs.RetentionDays.ONE_WEEK,
        encryption_key=key,
        removal_policy=RemovalPolicy.DESTROY,
    )
    role = iam.Role(stack, "IngestRole", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
    log_group.grant_write(role)
    key.grant_encrypt_decrypt(role)
    role.add_to_policy(
        iam.PolicyStatement(
            actions=["s3:ListBucket", "s3:GetBucketLocation"], resources=[lake.bucket_arn]
        )
    )
    role.add_to_policy(
        iam.PolicyStatement(
            actions=["s3:GetObject", "s3:PutObject", "s3:AbortMultipartUpload"],
            resources=[
                lake.arn_for_objects(f"{path}/*") for path in ("snapshots", "iceberg", "control")
            ],
        )
    )
    role.add_to_policy(
        iam.PolicyStatement(
            actions=["glue:GetDatabase", "glue:GetTable", "glue:UpdateTable"],
            resources=[
                stack.format_arn(service="glue", resource="catalog"),
                stack.format_arn(
                    service="glue", resource="database", resource_name=settings.database
                ),
                stack.format_arn(
                    service="glue", resource="table", resource_name=f"{settings.database}/*"
                ),
            ],
        )
    )
    role.add_to_policy(
        iam.PolicyStatement(
            actions=["ssm:GetParameter"],
            resources=[
                stack.format_arn(
                    service="ssm", resource="parameter", resource_name=f"aegis/dev/{name}"
                )
                for name in SECRET_KEYS
            ],
        )
    )
    worker = lambda_.DockerImageFunction(
        stack,
        "Ingest",
        function_name=f"{prefix}-ingest",
        architecture=lambda_.Architecture.ARM_64,
        code=lambda_.DockerImageCode.from_image_asset(
            str(ROOT),
            file="infra/Dockerfile",
            platform=ecr_assets.Platform.LINUX_ARM64,
            ignore_mode=IgnoreMode.DOCKER,
        ),
        timeout=Duration.seconds(LAMBDA_TIMEOUT),
        memory_size=2048,
        ephemeral_storage_size=Size.gibibytes(2),
        reserved_concurrent_executions=1,
        retry_attempts=0,
        max_event_age=Duration.minutes(10),
        role=role,
        log_group=log_group,
        environment={
            "AEGIS_LAKE_BUCKET": lake.bucket_name,
            "AEGIS_GLUE_DATABASE": settings.database,
            "AEGIS_SSM_PATH": settings.secret_path,
            "POLARS_MAX_THREADS": "2",
        },
    )
    group = scheduler.CfnScheduleGroup(stack, "ScheduleGroup", name=prefix)
    schedule_name = f"{prefix}-feed-refresh"
    scheduler_role = iam.Role(
        stack,
        "SchedulerRole",
        assumed_by=iam.ServicePrincipal("scheduler.amazonaws.com").with_conditions(
            {
                "StringEquals": {"aws:SourceAccount": stack.account},
                "ArnEquals": {
                    "aws:SourceArn": stack.format_arn(
                        service="scheduler", resource="schedule-group", resource_name=prefix
                    )
                },
            }
        ),
    )
    worker.grant_invoke(scheduler_role)
    scheduler.CfnSchedule(
        stack,
        "Refresh",
        name=schedule_name,
        group_name=group.ref,
        state="ENABLED" if settings.schedule_enabled else "DISABLED",
        schedule_expression="rate(6 hours)",
        flexible_time_window=scheduler.CfnSchedule.FlexibleTimeWindowProperty(mode="OFF"),
        target=scheduler.CfnSchedule.TargetProperty(
            arn=worker.function_arn,
            role_arn=scheduler_role.role_arn,
            input='{"action":"ingest"}',
            retry_policy=scheduler.CfnSchedule.RetryPolicyProperty(
                maximum_event_age_in_seconds=600, maximum_retry_attempts=1
            ),
        ),
    )
    for name, value in {
        "LakeBucket": lake.bucket_name,
        "ResultsBucket": results.bucket_name,
        "GlueDatabase": db.ref,
        "Workgroup": workgroup.ref,
        "KmsKey": key.key_arn,
        "IngestFunction": worker.function_name,
        "ScheduleGroupName": group.ref,
        "ScheduleName": schedule_name,
    }.items():
        CfnOutput(stack, name, value=value)
    return stack


if __name__ == "__main__":
    app = App()
    lake_stack(app, Settings.load(offline=os.getenv("AEGIS_CDK_OFFLINE") == "1"))
    app.synth()
