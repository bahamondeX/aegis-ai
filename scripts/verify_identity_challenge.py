"""Verify Cognito password and TOTP challenges with a scoped disposable identity."""

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time

from botocore.exceptions import ClientError

from infra.agent_deploy import existing_stack, outputs
from infra.hosting_preflight import hosting_budget
from infra.settings import SDK_CONFIG, Settings
from pipelines.config import project_environment
from pipelines.io import DataError


def code(secret: str) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    moving_factor = struct.pack(">Q", int(time.time()) // 30)
    digest = hmac.new(key, moving_factor, hashlib.sha1).digest()
    index = digest[-1] & 15
    return f"{(int.from_bytes(digest[index : index + 4], 'big') & 0x7FFF_FFFF) % 1_000_000:06d}"


def main() -> None:
    env = project_environment()
    settings = Settings.load(environment=env)
    hosting_budget(settings, env)
    session, _ = settings.identity()
    cfn = session.client("cloudformation", config=SDK_CONFIG)
    stack = existing_stack(cfn, f"{settings.project}-identity", settings)
    if stack is None:
        raise DataError("verification requires the owned Cognito stack")
    identity = outputs(stack)
    user = f"aegis-validation-challenge-{secrets.token_hex(6)}"
    info = {"UserPoolId": identity["PoolId"], "Username": user}
    client = session.client("cognito-idp", config=SDK_CONFIG)
    options = {"ClientId": identity["BrowserClientId"]}
    temporary, replacement = ("Aa9!" + secrets.token_urlsafe(30) for _ in range(2))

    def authenticate(password: str) -> dict:
        return client.initiate_auth(
            **options,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": user, "PASSWORD": password},
        )

    def challenge(initial: dict, key: str, response: str) -> dict:
        return client.respond_to_auth_challenge(
            **options,
            ChallengeName=initial["ChallengeName"],
            Session=initial["Session"],
            ChallengeResponses={"USERNAME": user, key: response},
        )

    created = False
    try:
        client.admin_create_user(**info, TemporaryPassword=temporary, MessageAction="SUPPRESS")
        created = True
        first = authenticate(temporary)
        if first.get("ChallengeName") != "NEW_PASSWORD_REQUIRED":
            raise DataError("Cognito accepted first sign-in without a password challenge")
        signed = challenge(first, "NEW_PASSWORD", replacement)
        if client.admin_get_user(**info)["UserStatus"] != "CONFIRMED":
            raise DataError("Cognito did not confirm the changed password")
        access = signed["AuthenticationResult"]["AccessToken"]
        seed = client.associate_software_token(AccessToken=access)["SecretCode"]
        enrollment_step = int(time.time()) // 30
        verified = client.verify_software_token(AccessToken=access, UserCode=code(seed))
        if verified.get("Status") != "SUCCESS":
            raise DataError("Cognito did not verify the authenticator")
        client.set_user_mfa_preference(
            AccessToken=access,
            SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
        )
        # Cognito rejects reuse of the code that verified the authenticator.
        time.sleep(max(0.0, (enrollment_step + 1) * 30 + 1 - time.time()))
        enrolled = authenticate(replacement)
        if enrolled.get("ChallengeName") != "SOFTWARE_TOKEN_MFA":
            raise DataError("the subsequent authentication did not enforce TOTP")
        if not challenge(enrolled, "SOFTWARE_TOKEN_MFA_CODE", code(seed)).get(
            "AuthenticationResult"
        ):
            raise DataError("Cognito did not complete the enforced TOTP challenge")
        print(json.dumps({"new_password_required": True, "subsequent_mfa_required": True}))
    except ClientError as error:
        raise SystemExit(
            f"Cognito {error.operation_name} failed ({error.response['Error']['Code']})"
        ) from None
    finally:
        if created:
            client.admin_disable_user(**info)
            print(json.dumps({"temporary_identity_disabled": True}))


if __name__ == "__main__":
    main()
