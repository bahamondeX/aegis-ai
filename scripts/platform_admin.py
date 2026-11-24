"""Invite and onboard the platform administrator using private Cognito delivery."""

import argparse
import hmac
import secrets
import subprocess
import sys
from base64 import b32decode
from datetime import UTC, datetime
from getpass import getpass
from pathlib import Path
from time import time
from urllib.parse import quote, urlencode
from uuid import UUID

from botocore.config import Config
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


def display_authenticator_setup(uri: str, setup_key: str, entry: str) -> None:
    # Keep the enrollment secret in stdin and the owner's terminal only.
    with open("/dev/tty", "w") as terminal:
        try:
            result = subprocess.run(
                ["/usr/bin/swift", str(Path(__file__).with_name("platform_admin_qr.swift"))],
                input=uri,
                text=True,
                capture_output=True,
                check=True,
                timeout=30,
            )
            rows = result.stdout.splitlines()
            if set("".join(rows)) != {"0", "1"} or any(len(row) != len(rows) for row in rows):
                raise ValueError("invalid QR matrix")
        except (OSError, subprocess.SubprocessError, ValueError):
            print(
                "Terminal QR unavailable. Add a time-based account using the setup key below.",
                file=terminal,
            )
        else:
            print(
                "In your phone's authenticator, add an account and scan this QR code.",
                file=terminal,
            )
            border = "0" * (len(rows) + 8)
            padded = [border] * 4 + ["0000" + row + "0000" for row in rows] + [border] * 4
            if len(padded) % 2:
                padded.append(border)
            colors = {"0": 255, "1": 0}
            for top, bottom in zip(padded[::2], padded[1::2], strict=True):
                line = []
                previous = None
                for pair in zip(top, bottom, strict=True):
                    if pair != previous:
                        fg, bg = (colors[pixel] for pixel in pair)
                        line.append(f"\033[38;2;{fg};{fg};{fg};48;2;{bg};{bg};{bg}m")
                        previous = pair
                    line.append("▀")
                print("".join(line) + "\033[0m", file=terminal)
        print(f"Use the new authenticator entry named {entry}.", file=terminal)
        print(f"Manual setup key for {entry}: {setup_key}", file=terminal)
        print("Keep the QR and setup key private.", file=terminal)


def totp_code(key: bytes, step: int) -> str:
    digest = hmac.digest(key, step.to_bytes(8, "big"), "sha1")
    offset = digest[-1] & 15
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFF_FFFF
    return f"{value % 1_000_000:06d}"


def verify_admin_totp(client, access: str, setup_key: str, entry: str) -> None:
    key = b32decode(setup_key + "=" * (-len(setup_key) % 8))
    code = getpass(f"Six-digit code from {entry} (Enter cancels): ").strip()
    if not code:
        raise DataError("authenticator setup was cancelled")
    step = int(time()) // 30
    if not (
        len(code) == 6
        and code.isascii()
        and code.isdecimal()
        and any(
            hmac.compare_digest(code, totp_code(key, candidate))
            for candidate in range(max(0, step - 1), step + 2)
        )
    ):
        raise DataError(
            f"Code does not match {entry} at the current time. Cognito was not contacted."
        )
    try:
        result = client.verify_software_token(AccessToken=access, UserCode=code)
    except (
        client.exceptions.CodeMismatchException,
        client.exceptions.EnableSoftwareTokenMFAException,
    ):
        raise DataError(
            "Cognito rejected a locally matched code. Check device time before retrying."
        ) from None
    if result.get("Status") != "SUCCESS":
        raise DataError("Cognito did not verify the authenticator")


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
            setup_key = client.associate_software_token(AccessToken=access)["SecretCode"]
            setup = f"Admin {secrets.token_hex(3).upper()}"
            entry = f"AEGIS {setup}"
            label = f"AEGIS:{quote(setup, safe='')}"
            params = urlencode(
                {
                    "secret": setup_key,
                    "issuer": "AEGIS",
                    "algorithm": "SHA1",
                    "digits": 6,
                    "period": 30,
                }
            )
            display_authenticator_setup(f"otpauth://totp/{label}?{params}", setup_key, entry)
            verifier = session.client(
                "cognito-idp",
                config=SDK_CONFIG.merge(
                    Config(retries={"mode": "standard", "total_max_attempts": 1})
                ),
            )
            verify_admin_totp(verifier, access, setup_key, entry)
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
    except DataError as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
