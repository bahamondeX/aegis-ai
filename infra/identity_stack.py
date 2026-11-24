"""Extend the existing Cognito directory without changing its resource IDs."""

from hashlib import sha256

from aws_cdk import (
    App,
    ArnFormat,
    BootstraplessSynthesizer,
    CfnCondition,
    CfnOutput,
    CfnParameter,
    Duration,
    Environment,
    Fn,
    RemovalPolicy,
    Stack,
    Tags,
    Token,
)
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as functions
from aws_cdk import aws_logs as logs

from backend.identity import ADMIN_EMAIL, ADMIN_USERNAME
from infra.settings import Settings

CALLBACK = "http://localhost:3000/auth/callback"
LOGOUT = "http://localhost:3000/"


def identity_stack(app: App, settings: Settings) -> Stack:
    stack = Stack(
        app,
        f"{settings.project}-identity",
        env=Environment(account=settings.account, region=settings.region),
        synthesizer=BootstraplessSynthesizer(),
        description="AEGIS Cognito registration, OAuth PKCE and administrative identity.",
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
    existing_pool = CfnParameter(
        stack,
        "ExistingPoolId",
        type="String",
        allowed_pattern=rf"{settings.region}_[A-Za-z0-9]+",
        description="Physical ID of the owned Cognito pool being extended.",
    )
    registration_log = logs.LogGroup(
        stack,
        "RegistrationLog",
        retention=logs.RetentionDays.ONE_WEEK,
    )
    registration = functions.Function(
        stack,
        "RegistrationGuard",
        code=functions.Code.from_inline(
            "def handler(event, context):\n"
            "    if event['triggerSource'] != 'PreSignUp_AdminCreateUser':\n"
            "        attrs = event['request']['userAttributes']\n"
            "        email = attrs.get('email', '').strip().casefold()\n"
            f"        if (email == {ADMIN_EMAIL!r} or not email or "
            f"event['userName'].strip().casefold() == {ADMIN_USERNAME!r}):\n"
            "            raise ValueError('This registration is unavailable')\n"
            "    return event\n"
        ),
        handler="index.handler",
        runtime=functions.Runtime.PYTHON_3_12,
        architecture=functions.Architecture.ARM_64,
        timeout=Duration.seconds(3),
        reserved_concurrent_executions=2,
        log_group=registration_log,
    )
    registration.add_permission(
        "CognitoRegistration",
        principal=iam.ServicePrincipal("cognito-idp.amazonaws.com"),
        source_account=settings.account,
        source_arn=stack.format_arn(
            service="cognito-idp",
            resource="userpool",
            resource_name=existing_pool.value_as_string,
            arn_format=ArnFormat.SLASH_RESOURCE_NAME,
        ),
    )
    pool = cognito.CfnUserPool(
        stack,
        "Pool",
        user_pool_name=f"{settings.project}-operators",
        user_pool_tier="LITE",
        deletion_protection="ACTIVE",
        admin_create_user_config=cognito.CfnUserPool.AdminCreateUserConfigProperty(
            allow_admin_create_user_only=False
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
        auto_verified_attributes=["email"],
        user_attribute_update_settings=cognito.CfnUserPool.UserAttributeUpdateSettingsProperty(
            attributes_require_verification_before_update=["email"],
        ),
        mfa_configuration="OPTIONAL",
        enabled_mfas=["SOFTWARE_TOKEN_MFA"],
        lambda_config=cognito.CfnUserPool.LambdaConfigProperty(
            pre_sign_up=registration.function_arn
        ),
        account_recovery_setting=cognito.CfnUserPool.AccountRecoverySettingProperty(
            recovery_mechanisms=[
                cognito.CfnUserPool.RecoveryOptionProperty(name="verified_email", priority=1)
            ]
        ),
    )
    pool.apply_removal_policy(RemovalPolicy.RETAIN)
    pool.add_metadata(
        "com.aws.cloudformation.Context",
        {
            "why": "Issue short-lived OAuth access tokens for the AEGIS workspace.",
            "must": "Guard reserved account registration and retain the directory.",
        },
    )
    hosted = CfnParameter(
        stack,
        "HostedOrigin",
        type="String",
        default="",
        allowed_pattern=r"(?:https://[a-z0-9]+\.cloudfront\.net)?",
        description="Exact CloudFront origin for the separately authorized hosted pilot.",
    )
    has_hosted = CfnCondition(
        stack,
        "HasHostedOrigin",
        expression=Fn.condition_not(Fn.condition_equals(hosted.value_as_string, "")),
    )
    google = CfnParameter(
        stack,
        "EnableGoogle",
        type="String",
        default="no",
        allowed_values=["yes", "no"],
    )
    google_enabled = CfnCondition(
        stack,
        "GoogleConfigured",
        expression=Fn.condition_equals(google.value_as_string, "yes"),
    )
    providers = Token.as_list(
        Fn.condition_if(google_enabled.logical_id, ["COGNITO", "Google"], ["COGNITO"])
    )
    callbacks = Token.as_list(
        Fn.condition_if(
            has_hosted.logical_id,
            [CALLBACK, f"{hosted.value_as_string}/auth/callback"],
            [CALLBACK],
        )
    )
    logouts = Token.as_list(
        Fn.condition_if(
            has_hosted.logical_id,
            [LOGOUT, f"{hosted.value_as_string}/"],
            [LOGOUT],
        )
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
        callback_ur_ls=callbacks,
        logout_ur_ls=logouts,
        supported_identity_providers=providers,
        explicit_auth_flows=["ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_PASSWORD_AUTH"],
        read_attributes=["email", "email_verified"],
        write_attributes=["email"],
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
    cognito.CfnUserPoolGroup(
        stack, "Administrators", user_pool_id=pool.ref, group_name=f"{settings.project}-admins"
    )
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
