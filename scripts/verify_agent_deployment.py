"""Check deployed AEGIS identity, encryption, role and runtime controls."""

import json

from infra.operations import stack_outputs
from infra.settings import SDK_CONFIG, Settings
from pipelines.io import DataError


def main() -> None:
    settings = Settings.load()
    session, _ = settings.identity()
    stacks = session.client("cloudformation", config=SDK_CONFIG)

    def outputs(suffix: str) -> dict[str, str]:
        stack = stacks.describe_stacks(StackName=f"{settings.project}-{suffix}")["Stacks"][0]
        tags = {item["Key"]: item["Value"] for item in stack["Tags"]}
        if tags.get("Project") != "AEGIS" or tags.get("AegisScope") != settings.project:
            raise DataError("AWS stack ownership differs")
        return {row["OutputKey"]: row["OutputValue"] for row in stack["Outputs"]}

    identity = outputs("identity")
    service = outputs("agent")
    lake = stack_outputs(session, settings)
    control = session.client("bedrock-agentcore-control", config=SDK_CONFIG)
    runtime = control.get_agent_runtime(agentRuntimeId=service["RuntimeId"])
    endpoint = control.get_agent_runtime_endpoint(
        agentRuntimeId=service["RuntimeId"], endpointName="DEFAULT"
    )
    assert runtime["status"] == endpoint["status"] == "READY"
    lifecycle = runtime["lifecycleConfiguration"]
    assert lifecycle["maxLifetime"] == 120 and lifecycle["idleRuntimeSessionTimeout"] == 60
    authorizer = runtime["authorizerConfiguration"]["customJWTAuthorizer"]
    assert authorizer["allowedClients"] == [identity["BrowserClientId"]]
    cognito = session.client("cognito-idp", config=SDK_CONFIG)
    pool = cognito.describe_user_pool(UserPoolId=identity["PoolId"])["UserPool"]
    public = cognito.describe_user_pool_client(
        UserPoolId=identity["PoolId"], ClientId=identity["BrowserClientId"]
    )["UserPoolClient"]
    assert pool["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"]
    assert public["AllowedOAuthFlows"] == ["code"] and not public.get("ClientSecret")
    assert public["AccessTokenValidity"] == 10
    iam = session.client("iam", config=SDK_CONFIG)
    role = runtime["roleArn"].split("/")[-1]
    policy = iam.get_role_policy(RoleName=role, PolicyName="AegisRuntimeAccess")["PolicyDocument"][
        "Statement"
    ]
    actions = {
        action
        for row in policy
        for action in ([row["Action"]] if isinstance(row["Action"], str) else row["Action"])
    }
    assert "bedrock:InvokeModel" in actions and "glue:GetTable" in actions
    assert not actions.intersection({"s3:*", "s3:DeleteObject", "glue:UpdateTable", "iam:PassRole"})
    s3 = session.client("s3", config=SDK_CONFIG)
    bucket = {"Bucket": service["CheckpointBucket"], "ExpectedBucketOwner": settings.account}
    rule = s3.get_bucket_encryption(**bucket)["ServerSideEncryptionConfiguration"]["Rules"][0]
    encryption = rule["ApplyServerSideEncryptionByDefault"]
    assert (
        encryption["SSEAlgorithm"] == "aws:kms" and encryption["KMSMasterKeyID"] == lake["KmsKey"]
    )
    public_access = s3.get_public_access_block(**bucket)["PublicAccessBlockConfiguration"]
    assert len(public_access) == 4 and all(public_access.values())
    points = s3.list_objects_v2(**bucket, Prefix="checkpoints/run/", MaxKeys=2)["Contents"]
    assert points
    for item in points:
        checkpoint = s3.head_object(**bucket, Key=item["Key"])
        assert checkpoint["ServerSideEncryption"] == "aws:kms"
        assert checkpoint["SSEKMSKeyId"] == lake["KmsKey"]
    logs = session.client("logs", config=SDK_CONFIG)
    group = f"/aws/bedrock-agentcore/runtimes/{service['RuntimeId']}-DEFAULT"
    matches = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
    (description,) = [item for item in matches if item["logGroupName"] == group]
    assert description.get("retentionInDays") == 7
    print(
        json.dumps(
            {
                "runtime": service["RuntimeId"].rsplit("-", 1)[0],
                "status": endpoint["status"],
                "log_retention_days": description["retentionInDays"],
                "session_max_seconds": lifecycle["maxLifetime"],
                "session_idle_seconds": lifecycle["idleRuntimeSessionTimeout"],
                "checked_checkpoint_objects": len(points),
                "checkpoint_encryption": "project KMS",
                "cognito_invite_only": True,
                "access_token_minutes": public["AccessTokenValidity"],
                "scoped_iam_action_count": len(actions),
            }
        )
    )


if __name__ == "__main__":
    main()
