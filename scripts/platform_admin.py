"""Invite and onboard the platform administrator using private Cognito delivery."""

import argparse
import secrets
import sys
from datetime import UTC, datetime
from getpass import getpass
from urllib.parse import quote
from uuid import UUID

from botocore.exceptions import ClientError

from backend.identity import ADMIN_EMAIL, ADMIN_USERNAME, Audit, Decision, Status, attributes
from backend.investigations.store import S3Store, Store, Version
from infra.hosting_preflight import hosting_budget
from infra.settings import SDK_CONFIG, Settings
from pipelines.config import project_environment
from pipelines.io import DataError


def pending_decision(stored: Version | None) -> Decision:
    current = Decision.model_validate_json(stored.data) if stored else Decision()
    if current.status != Status.PENDING or current.audit or current.revoked_before:
        raise DataError("administrator account has an unexpected existing decision")
    return current


def activate_verified_admin(store: Store, subject: UUID, now: datetime) -> None:
    for _ in range(3):
        stored = store.get(str(subject))
        current = pending_decision(stored)
        current.status = Status.APPROVED
        current.revoked_before = int(now.timestamp())
        current.audit.append(
            Audit(actor=subject, target=subject, action="activate_admin", timestamp=now)
        )
        if store.put(
            str(subject), current.model_dump_json().encode(), stored.token if stored else None
        ):
            return
    raise DataError("the administrator decision changed during onboarding")


def verified_native_mfa(user: dict) -> bool:
    attrs = attributes(user)
    return (
        user["Username"] == ADMIN_USERNAME
        and user["Enabled"]
        and user["UserStatus"] == "CONFIRMED"
        and attrs.get("email") == ADMIN_EMAIL
        and attrs.get("email_verified") == "true"
        and not attrs.get("identities")
        and user.get("PreferredMfaSetting") == "SOFTWARE_TOKEN_MFA"
        and "SOFTWARE_TOKEN_MFA" in user.get("UserMFASettingList", [])
    )


def verify_admin_email(client, access: str) -> None:
    client.get_user_attribute_verification_code(AccessToken=access, AttributeName="email")
    print(f"Cognito sent a verification code to {ADMIN_EMAIL}. Open the newest message.")
    for attempt in range(3):
        try:
            client.verify_user_attribute(
                AccessToken=access,
                AttributeName="email",
                Code=getpass("Latest Cognito email verification code: ").strip(),
            )
            return
        except client.exceptions.CodeMismatchException:
            if attempt == 2:
                raise
            print("Code mismatch. Check the newest Cognito email and enter its six-digit code.")
        except client.exceptions.ExpiredCodeException:
            if attempt == 2:
                raise
            client.get_user_attribute_verification_code(AccessToken=access, AttributeName="email")
            print("The code expired. Cognito sent a new verification email.")


def verify_admin_totp(client, access: str) -> None:
    for attempt in range(3):
        try:
            result = client.verify_software_token(
                AccessToken=access,
                UserCode=getpass("Current six-digit code from your authenticator: ").strip(),
            )
            if result.get("Status") == "SUCCESS":
                return
        except client.exceptions.EnableSoftwareTokenMFAException:
            if attempt == 2:
                raise
        if attempt < 2:
            print("Check the authenticator entry for this setup and try its next code.")
    raise DataError("Cognito could not verify the authenticator")


def main() -> None:
    from infra.agent_deploy import existing_stack, outputs

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("invite", "onboard"))
    args = parser.parse_args()
    if args.operation == "onboard" and not sys.stdin.isatty():
        raise SystemExit("Administrator onboarding requires a private interactive terminal.")
    env = project_environment()
    settings = Settings.load(environment=env)
    hosting_budget(settings, env)
    session, _ = settings.identity()
    cfn = session.client("cloudformation", config=SDK_CONFIG)
    stacks = {}
    for part in ("identity", "agent", "lake"):
        stack = existing_stack(cfn, f"{settings.project}-{part}", settings)
        if stack is None:
            raise DataError(f"missing owned {part} stack")
        stacks[part] = outputs(stack)
    pool = stacks["identity"]["PoolId"]
    public = stacks["identity"]["BrowserClientId"]
    client = session.client("cognito-idp", config=SDK_CONFIG)
    identity = {"UserPoolId": pool, "Username": ADMIN_USERNAME}
    group = f"{settings.project}-admins"
    try:
        client.get_group(UserPoolId=pool, GroupName=group)
        try:
            user = client.admin_get_user(**identity)
        except client.exceptions.UserNotFoundException:
            if args.operation != "invite":
                raise DataError(
                    "the platform administrator invitation has not been issued"
                ) from None
            client.admin_create_user(
                **identity,
                TemporaryPassword="A9!" + secrets.token_urlsafe(32),
                UserAttributes=[{"Name": "email", "Value": ADMIN_EMAIL}],
                DesiredDeliveryMediums=["EMAIL"],
                ForceAliasCreation=False,
            )
            user = client.admin_get_user(**identity)
            print(f"Cognito issued the private invitation to {ADMIN_EMAIL}.", flush=True)
        attrs = attributes(user)
        if attrs.get("email") != ADMIN_EMAIL or attrs.get("identities") or not user["Enabled"]:
            raise DataError("the reserved administrator account differs from the expected identity")
        if args.operation == "invite":
            client.admin_add_user_to_group(**identity, GroupName=group)
            print("Administrator group assigned. Interactive onboarding is required.")
            return
        groups = client.admin_list_groups_for_user(**identity)["Groups"]
        if not any(item["GroupName"] == group for item in groups):
            raise DataError("the administrator account has no server-side role")
        store = S3Store(
            session.client("s3", config=SDK_CONFIG),
            stacks["agent"]["CheckpointBucket"],
            settings.account,
            stacks["lake"]["KmsKey"],
            namespace="identity/accounts",
        )
        subject = UUID(attrs["sub"])
        if stored := store.get(str(subject)):
            if Decision.model_validate_json(stored.data).status == Status.APPROVED:
                if not verified_native_mfa(user):
                    raise DataError(
                        "administrator approval exists but Cognito verification or MFA is missing"
                    )
                print("Administrator onboarding is already complete.")
                return
            pending_decision(stored)
        change_required = user["UserStatus"] == "FORCE_CHANGE_PASSWORD"
        password = getpass(
            "Cognito temporary password: " if change_required else "Current password: "
        )
        result = client.initiate_auth(
            ClientId=public,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": ADMIN_USERNAME, "PASSWORD": password},
        )
        del password
        if change_required:
            if result.get("ChallengeName") != "NEW_PASSWORD_REQUIRED":
                raise DataError("Cognito did not require a password change")
            print("Cognito required the NEW_PASSWORD_REQUIRED challenge.")
            replacement = getpass("New password (16 or more characters): ")
            if len(replacement) < 16 or getpass("Confirm new password: ") != replacement:
                raise DataError("the passwords differ or do not meet the length requirement")
            result = client.respond_to_auth_challenge(
                ClientId=public,
                ChallengeName="NEW_PASSWORD_REQUIRED",
                Session=result["Session"],
                ChallengeResponses={"USERNAME": ADMIN_USERNAME, "NEW_PASSWORD": replacement},
            )
            del replacement
        if result.get("ChallengeName") == "SOFTWARE_TOKEN_MFA":
            result = client.respond_to_auth_challenge(
                ClientId=public,
                ChallengeName="SOFTWARE_TOKEN_MFA",
                Session=result["Session"],
                ChallengeResponses={
                    "USERNAME": ADMIN_USERNAME,
                    "SOFTWARE_TOKEN_MFA_CODE": getpass("Authenticator code: "),
                },
            )
        access = result["AuthenticationResult"]["AccessToken"]
        current = attributes(client.admin_get_user(**identity))
        if current.get("email_verified") != "true":
            verify_admin_email(client, access)
        if "SOFTWARE_TOKEN_MFA" not in client.admin_get_user(**identity).get(
            "UserMFASettingList", []
        ):
            enrollment = client.associate_software_token(AccessToken=access)
            label = quote(f"AEGIS:{ADMIN_EMAIL}", safe="")
            uri = f"otpauth://totp/{label}?secret={enrollment['SecretCode']}&issuer=AEGIS"
            # Only the administrator's terminal receives the enrollment secret.
            with open("/dev/tty", "w") as terminal:
                print(
                    f"Add this authenticator URI privately, then clear terminal scrollback:\n{uri}",
                    file=terminal,
                )
            print("For manual setup, use the URI's secret value as the time-based setup key.")
            verify_admin_totp(client, access)
        client.set_user_mfa_preference(
            AccessToken=access,
            SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
        )
        user = client.admin_get_user(**identity)
        if not verified_native_mfa(user) or attributes(user)["sub"] != str(subject):
            raise DataError("Cognito did not confirm administrator verification and MFA")
        client.admin_user_global_sign_out(**identity)
        activate_verified_admin(store, subject, datetime.now(UTC))
        print("Administrator enabled. Sign in again with your password and authenticator.")
    except ClientError as error:
        raise SystemExit(
            f"Cognito {error.operation_name} failed ({error.response['Error']['Code']})"
        ) from None


if __name__ == "__main__":
    main()
