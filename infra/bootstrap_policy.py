"""CloudFormation execution permissions restricted to one AEGIS lake stack."""

import json
from typing import Any

from botocore.client import BaseClient

from infra.settings import Settings
from pipelines.io import DataError


def execution_policy(settings: Settings, partition: str) -> dict[str, Any]:
    statements: list[dict[str, Any]] = []

    def allow(service: str, names: str, resources: str | list[str], **condition: Any) -> None:
        statements.append(
            {
                "Effect": "Allow",
                "Action": [f"{service}:{action}" for action in names.split()],
                "Resource": resources,
                **({"Condition": condition} if condition else {}),
            }
        )

    def regional(service: str, resource: str) -> str:
        return f"arn:{partition}:{service}:{settings.region}:{settings.account}:{resource}"

    def iam(resource: str) -> str:
        return f"arn:{partition}:iam::{settings.account}:{resource}"

    bucket = f"arn:{partition}:s3:::{settings.stack}-*"
    function = regional("lambda", f"function:{settings.project}-ingest")
    group = regional("logs", f"log-group:/aws/lambda/{settings.project}-ingest")
    roles = [iam(f"role/{settings.stack}-{role}*") for role in ("IngestRole", "SchedulerRole")]
    key = regional("kms", "key/*")
    key_alias = regional("kms", f"alias/{settings.project}-lake")
    project_tag = {"aws:ResourceTag/AegisScope": settings.project}
    allow(
        "s3",
        "CreateBucket DeleteBucket ListBucket GetBucketLocation GetBucketTagging "
        "PutBucketTagging GetBucketVersioning PutBucketVersioning GetBucketPublicAccessBlock "
        "PutBucketPublicAccessBlock GetBucketOwnershipControls PutBucketOwnershipControls "
        "GetEncryptionConfiguration PutEncryptionConfiguration "
        "GetBucketPolicy PutBucketPolicy DeleteBucketPolicy GetLifecycleConfiguration "
        "PutLifecycleConfiguration GetBucketAcl",
        bucket,
    )
    allow("kms", "CreateKey", "*", StringEquals={"aws:RequestTag/AegisScope": settings.project})
    allow("kms", "TagResource", key, StringEquals={"aws:RequestTag/AegisScope": settings.project})
    allow(
        "kms",
        "DescribeKey EnableKeyRotation GetKeyRotationStatus GetKeyPolicy PutKeyPolicy "
        "UpdateKeyDescription ListResourceTags TagResource UntagResource "
        "CreateAlias DeleteAlias UpdateAlias ScheduleKeyDeletion CancelKeyDeletion",
        key,
        StringEquals=project_tag,
    )
    allow("kms", "CreateAlias DeleteAlias UpdateAlias", key_alias)
    allow("kms", "ListAliases", "*", StringEquals={"aws:RequestedRegion": settings.region})
    allow(
        "glue",
        "CreateDatabase DeleteDatabase GetDatabase UpdateDatabase",
        [regional("glue", "catalog"), regional("glue", f"database/{settings.database}")],
    )
    allow(
        "athena",
        "CreateWorkGroup DeleteWorkGroup GetWorkGroup UpdateWorkGroup "
        "TagResource UntagResource ListTagsForResource",
        regional("athena", f"workgroup/{settings.project}"),
    )
    allow(
        "lambda",
        "CreateFunction DeleteFunction GetFunction GetFunctionConfiguration "
        "UpdateFunctionCode UpdateFunctionConfiguration GetFunctionConcurrency "
        "PutFunctionConcurrency DeleteFunctionConcurrency GetFunctionEventInvokeConfig "
        "PutFunctionEventInvokeConfig UpdateFunctionEventInvokeConfig "
        "DeleteFunctionEventInvokeConfig ListTags TagResource UntagResource",
        [function, f"{function}:*"],
    )
    allow(
        "ecr",
        "BatchGetImage GetDownloadUrlForLayer DescribeImages "
        "GetRepositoryPolicy SetRepositoryPolicy",
        regional(
            "ecr",
            f"repository/cdk-{settings.bootstrap_qualifier}-container-assets-"
            f"{settings.account}-{settings.region}",
        ),
    )
    allow(
        "logs",
        "CreateLogGroup DeleteLogGroup PutRetentionPolicy DeleteRetentionPolicy "
        "AssociateKmsKey DisassociateKmsKey ListTagsForResource ListTagsLogGroup "
        "TagLogGroup UntagLogGroup TagResource UntagResource",
        [group, f"{group}:*"],
    )
    allow("logs", "DescribeLogGroups", "*", StringEquals={"aws:RequestedRegion": settings.region})
    allow(
        "iam",
        "CreateRole DeleteRole GetRole UpdateRole UpdateAssumeRolePolicy "
        "PutRolePolicy GetRolePolicy DeleteRolePolicy ListRolePolicies ListAttachedRolePolicies "
        "TagRole UntagRole ListRoleTags",
        roles,
    )
    allow(
        "iam",
        "PassRole",
        roles,
        StringEquals={"iam:PassedToService": ["lambda.amazonaws.com", "scheduler.amazonaws.com"]},
    )
    allow(
        "scheduler",
        "CreateScheduleGroup GetScheduleGroup DeleteScheduleGroup "
        "TagResource UntagResource ListTagsForResource",
        regional("scheduler", f"schedule-group/{settings.project}"),
    )
    allow(
        "scheduler",
        "CreateSchedule GetSchedule UpdateSchedule DeleteSchedule",
        regional("scheduler", f"schedule/{settings.project}/{settings.project}-feed-refresh"),
    )
    # AWS checks group-wide DeleteSchedule when deleting even an empty schedule group.
    allow("scheduler", "DeleteSchedule", regional("scheduler", f"schedule/{settings.project}/*"))
    allow(
        "ssm",
        "GetParameter GetParameters",
        regional("ssm", f"parameter/cdk-bootstrap/{settings.bootstrap_qualifier}/version"),
    )
    return {"Version": "2012-10-17", "Statement": statements}


def prepare_policy(client: BaseClient, settings: Settings, partition: str) -> str:
    name = f"{settings.stack}-execution"
    path = f"/aegis/{settings.project}/"
    arn = f"arn:{partition}:iam::{settings.account}:policy{path}{name}"
    document = execution_policy(settings, partition)
    body = json.dumps(document, separators=(",", ":"))
    if len(body) > 6144:
        raise DataError("project deployment policy exceeds the IAM managed-policy size limit")
    tags = {"Project": "AEGIS", "Environment": "dev", "AegisScope": settings.project}
    try:
        existing = client.get_policy(PolicyArn=arn)["Policy"]
    except client.exceptions.NoSuchEntityException:
        client.create_policy(
            PolicyName=name,
            Path=path,
            PolicyDocument=body,
            Tags=[{"Key": key, "Value": value} for key, value in tags.items()],
        )
    else:
        seen_tags = {
            tag["Key"]: tag["Value"] for tag in client.list_policy_tags(PolicyArn=arn)["Tags"]
        }
        version = client.get_policy_version(PolicyArn=arn, VersionId=existing["DefaultVersionId"])[
            "PolicyVersion"
        ]
        if seen_tags != tags or version["Document"] != document:
            raise DataError("existing project execution policy differs from the reviewed policy")
    return arn
