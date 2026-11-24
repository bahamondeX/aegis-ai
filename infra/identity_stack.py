"""Private Cognito directory for the explicitly authorized AEGIS runtime."""

from hashlib import sha256

from aws_cdk import (
    App,
    BootstraplessSynthesizer,
    CfnOutput,
    Environment,
    RemovalPolicy,
    Stack,
    Tags,
)
from aws_cdk import aws_cognito as cognito

from infra.settings import Settings

CALLBACK = "http://localhost:3000/auth/callback"
LOGOUT = "http://localhost:3000/"


def identity_stack(app: App, settings: Settings) -> Stack:
    stack = Stack(
        app,
        f"{settings.project}-identity",
        env=Environment(account=settings.account, region=settings.region),
        synthesizer=BootstraplessSynthesizer(),
        description="Invite-only AEGIS Cognito public OAuth client and workspace group.",
    )
    for key, value in {
        "Project": "AEGIS",
        "Environment": "dev",
        "AegisScope": settings.project,
    }.items():
        Tags.of(stack).add(key, value)
    stack.template_options.metadata = {
        "AWSToolsMetrics": {"AWSAgentToolkit": "aws-cloudformation@3"}
    }
    pool = cognito.CfnUserPool(
        stack,
        "Pool",
        user_pool_name=f"{settings.project}-operators",
        user_pool_tier="LITE",
        deletion_protection="ACTIVE",
        admin_create_user_config=cognito.CfnUserPool.AdminCreateUserConfigProperty(
            allow_admin_create_user_only=True
        ),
        policies=cognito.CfnUserPool.PoliciesProperty(
            password_policy=cognito.CfnUserPool.PasswordPolicyProperty(
                minimum_length=16,
                require_lowercase=True,
                require_numbers=True,
                require_symbols=True,
                require_uppercase=True,
                temporary_password_validity_days=1,
            ),
        ),
        username_configuration=cognito.CfnUserPool.UsernameConfigurationProperty(
            case_sensitive=False
        ),
        account_recovery_setting=cognito.CfnUserPool.AccountRecoverySettingProperty(
            recovery_mechanisms=[
                cognito.CfnUserPool.RecoveryOptionProperty(name="admin_only", priority=1)
            ]
        ),
    )
    pool.apply_removal_policy(RemovalPolicy.RETAIN)
    pool.add_metadata(
        "com.aws.cloudformation.Context",
        {
            "why": "Issue short-lived OAuth access tokens for the AEGIS workspace.",
            "must": "Require administrator invitations and retain the directory.",
        },
    )
    public_client = cognito.CfnUserPoolClient(
        stack,
        "Browser",
        user_pool_id=pool.ref,
        client_name=f"{settings.project}-browser",
        generate_secret=False,
        allowed_o_auth_flows=["code"],
        allowed_o_auth_flows_user_pool_client=True,
        allowed_o_auth_scopes=["openid"],
        callback_ur_ls=[CALLBACK],
        logout_ur_ls=[LOGOUT],
        supported_identity_providers=["COGNITO"],
        explicit_auth_flows=["ALLOW_REFRESH_TOKEN_AUTH"],
        prevent_user_existence_errors="ENABLED",
        access_token_validity=10,
        id_token_validity=10,
        refresh_token_validity=1,
        enable_token_revocation=True,
        token_validity_units=cognito.CfnUserPoolClient.TokenValidityUnitsProperty(
            access_token="minutes", id_token="minutes", refresh_token="days"
        ),
    )
    public_client.add_metadata(
        "com.aws.cloudformation.Context",
        {
            "why": "Public app client for browser Authorization Code with PKCE.",
            "must": "Use the code flow and explicit redirects, with no application secret.",
        },
    )
    cognito.CfnUserPoolGroup(stack, "Workspace", user_pool_id=pool.ref, group_name=settings.project)
    suffix = sha256(f"{settings.account}/{settings.region}".encode()).hexdigest()[:10]
    domain = cognito.CfnUserPoolDomain(
        stack,
        "Login",
        domain=f"{settings.project}-ops-{suffix}",
        user_pool_id=pool.ref,
        managed_login_version=1,
    )
    CfnOutput(stack, "PoolId", value=pool.ref)
    CfnOutput(stack, "BrowserClientId", value=public_client.ref)
    CfnOutput(stack, "LoginDomain", value=domain.ref)
    return stack
