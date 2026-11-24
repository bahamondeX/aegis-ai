"""Current authorization and an atomic, encrypted account decision history."""

import json
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from boto3 import Session
from botocore.client import BaseClient
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from backend.investigations.store import S3Store, Store
from backend.models import ServiceError

ADMIN_USERNAME = "aegis-platform-admin"
ADMIN_EMAIL = "admin@oscarbahamonde.com"


class Status(StrEnum):
    PENDING = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    SUSPENDED = "SUSPENDED"


class Audit(BaseModel):
    actor: UUID
    target: UUID
    action: str
    timestamp: datetime
    outcome: Literal["applied"] = "applied"


class Decision(BaseModel):
    status: Status = Status.PENDING
    revoked_before: int = 0
    audit: list[Audit] = Field(default_factory=list)
    revoked_sessions: dict[str, datetime] = Field(default_factory=dict)


class Account(BaseModel):
    subject: UUID
    username: str
    email: str | None
    email_verified: bool
    registered_at: datetime
    provider: Literal["email", "Google", "other"]
    status: Status
    administrator: bool = False
    enabled: bool

    @property
    def can_access(self) -> bool:
        return (
            self.enabled
            and self.email_verified
            and self.status == Status.APPROVED
            and (self.username != ADMIN_USERNAME or self.administrator)
        )


class Change(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["approve", "reject", "suspend", "restore"]
    expected_status: Status


TRANSITIONS = {
    (Status.PENDING, "approve"): Status.APPROVED,
    (Status.PENDING, "reject"): Status.REJECTED,
    (Status.APPROVED, "suspend"): Status.SUSPENDED,
    (Status.SUSPENDED, "restore"): Status.APPROVED,
}


def attributes(user: dict[str, Any]) -> dict[str, str]:
    return {
        item["Name"]: item["Value"]
        for item in user.get("UserAttributes", user.get("Attributes", []))
    }


class Directory:
    def __init__(self, client: BaseClient, pool: str, store: Store, admin_group: str) -> None:
        self.client = client
        self.pool = pool
        self.store = store
        self.admin_group = admin_group

    def _call(self, operation: str, **kwargs: Any) -> dict[str, Any]:
        try:
            return getattr(self.client, operation)(UserPoolId=self.pool, **kwargs)
        except (ClientError, BotoCoreError) as error:
            if (
                isinstance(error, ClientError)
                and error.response["Error"]["Code"] == "UserNotFoundException"
            ):
                raise ServiceError("account_missing", "account was not found", 404) from None
            raise ServiceError(
                "directory_unavailable", "account directory is temporarily unavailable", 503
            ) from None

    def decision(self, subject: UUID) -> tuple[Decision, str | None]:
        try:
            stored = self.store.get(str(subject))
            if stored is None:
                return Decision(), None
            return Decision.model_validate_json(stored.data), stored.token
        except (ClientError, BotoCoreError, ValidationError):
            raise ServiceError(
                "directory_unavailable", "account decisions are temporarily unavailable", 503
            ) from None

    def _account(
        self, user: dict[str, Any], decision: Decision, *, check_admin: bool = False
    ) -> Account:
        attrs = attributes(user)
        identities = json.loads(attrs.get("identities", "[]"))
        subject = UUID(attrs["sub"])
        name = user["Username"]
        email = attrs.get("email")
        verified = attrs.get("email_verified") == "true"
        admin = False
        if (
            check_admin
            and name == ADMIN_USERNAME
            and email == ADMIN_EMAIL
            and verified
            and not identities
            and user.get("UserStatus") == "CONFIRMED"
            and user.get("PreferredMfaSetting") == "SOFTWARE_TOKEN_MFA"
            and "SOFTWARE_TOKEN_MFA" in user.get("UserMFASettingList", [])
        ):
            groups = self._call("admin_list_groups_for_user", Username=name, Limit=60)
            admin = any(group["GroupName"] == self.admin_group for group in groups["Groups"])
        return Account(
            subject=subject,
            username=name,
            email=email,
            email_verified=verified,
            registered_at=user["UserCreateDate"],
            provider=(
                "Google"
                if any(i.get("providerName") == "Google" for i in identities)
                else "other"
                if identities
                else "email"
            ),
            status=decision.status,
            administrator=admin,
            enabled=user["Enabled"],
        )

    def signed_in(self, claims: dict[str, Any]) -> Account:
        name, issued, authenticated = (claims.get(k) for k in ("username", "iat", "auth_time"))
        if (
            not isinstance(name, str)
            or not name
            or type(issued) is not int
            or type(authenticated) is not int
            or authenticated > issued
        ):
            raise ServiceError("unauthorized", "invalid account token", 401)
        try:
            user = self._call("admin_get_user", Username=name)
        except ServiceError as error:
            if error.status == 404:
                raise ServiceError("unauthorized", "account is unavailable", 401) from None
            raise
        subject = UUID(attributes(user)["sub"])
        decision, _ = self.decision(subject)
        account = self._account(user, decision, check_admin=True)
        if (
            str(subject) != claims["sub"]
            or not account.enabled
            or authenticated <= decision.revoked_before
            or claims.get("origin_jti") in decision.revoked_sessions
        ):
            raise ServiceError("unauthorized", "sign in again to continue", 401)
        return account

    def users(self) -> list[Account]:
        users: list[Account] = []
        cursor = None
        for _ in range(10):
            result = self._call(
                "list_users", Limit=60, **({"PaginationToken": cursor} if cursor else {})
            )
            for user in result["Users"]:
                decision, _ = self.decision(UUID(attributes(user)["sub"]))
                users.append(self._account(user, decision))
            cursor = result.get("PaginationToken")
            if not cursor:
                return sorted(users, key=lambda user: user.registered_at, reverse=True)
        raise ServiceError("directory_limit", "directory exceeds the pilot listing limit", 503)

    def audit(self, name: str) -> list[Audit]:
        user = self._call("admin_get_user", Username=name)
        return self.decision(UUID(attributes(user)["sub"]))[0].audit

    def change(self, actor: Account, name: str, change: Change) -> Account:
        if name == ADMIN_USERNAME:
            raise ServiceError(
                "protected_account", "the platform administrator is managed separately", 403
            )
        user = self._call("admin_get_user", Username=name)
        current, version = self.decision(UUID(attributes(user)["sub"]))
        target = self._account(user, current)
        next_status = TRANSITIONS.get((current.status, change.action))
        if current.status != change.expected_status or next_status is None:
            raise ServiceError(
                "invalid_transition", "the account changed or this action is unavailable", 409
            )
        if next_status == Status.APPROVED and not (target.email_verified and target.enabled):
            raise ServiceError(
                "verification_required", "the account must have verified its email", 409
            )
        now = datetime.now(UTC)
        event = Audit(
            actor=actor.subject, target=target.subject, action=change.action, timestamp=now
        )
        value = Decision(
            status=next_status,
            revoked_sessions=current.revoked_sessions,
            revoked_before=int(now.timestamp())
            if change.action in ("suspend", "reject")
            else current.revoked_before,
            audit=[*current.audit, event],
        )
        self.write(target.subject, value, version)
        return target.model_copy(update={"status": next_status})

    def logout(self, claims: dict[str, Any]) -> None:
        account = self.signed_in(claims)
        try:
            session = str(UUID(claims["origin_jti"]))
        except (KeyError, ValueError, TypeError, AttributeError):
            raise ServiceError("unauthorized", "session identifier was unavailable", 401) from None
        now = datetime.now(UTC)
        for _ in range(3):
            current, version = self.decision(account.subject)
            keep = {key: expiry for key, expiry in current.revoked_sessions.items() if expiry > now}
            if session in keep:
                return
            keep[session] = now + timedelta(days=1, minutes=10)
            if len(keep) > 1000:
                raise ServiceError("session_limit", "too many sessions were closed", 429)
            current.revoked_sessions = keep
            try:
                self.write(account.subject, current, version)
            except ServiceError as error:
                if error.code != "decision_conflict":
                    raise
            else:
                return
        raise ServiceError("decision_conflict", "sign-out conflicted, retry", 409)

    def write(self, subject: UUID, decision: Decision, version: str | None) -> None:
        try:
            saved = self.store.put(str(subject), decision.model_dump_json().encode(), version)
        except (ClientError, BotoCoreError):
            raise ServiceError(
                "directory_unavailable", "the decision could not be recorded", 503
            ) from None
        if not saved:
            raise ServiceError(
                "decision_conflict", "the account changed, reload and try again", 409
            )


def cloud_directory(
    session: Session, environment: dict[str, str], account: str, config: Config
) -> Directory:
    return Directory(
        session.client("cognito-idp", config=config),
        environment["AEGIS_OIDC_ISSUER"].rsplit("/", 1)[1],
        S3Store(
            session.client("s3", config=config),
            environment["AEGIS_IDENTITY_BUCKET"],
            account,
            environment["AEGIS_LAKE_KMS_ARN"],
            namespace="identity/accounts",
        ),
        environment["AEGIS_PROJECT_PREFIX"] + "-admins",
    )
