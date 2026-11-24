"""JWT verification for one authorized workspace."""

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

import jwt

from backend.identity import Account, Directory
from backend.models import ServiceError

LOCAL_ISSUER = "aegis-local"
LOCAL_AUDIENCE = "aegis-local-api"


class Auth:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        workspace: str,
        local_key: str | None = None,
        jwks_url: str | None = None,
        cognito: bool = False,
        directory: Directory | None = None,
    ) -> None:
        if (
            not issuer
            or not audience
            or not workspace
            or bool(local_key) == bool(jwks_url)
            or (cognito and not jwks_url)
            or (directory is not None and not cognito)
        ):
            raise ValueError("configure exactly one JWT authentication mode")
        if local_key is not None and (
            len(local_key) < 32 or issuer != LOCAL_ISSUER or audience != LOCAL_AUDIENCE
        ):
            raise ValueError("invalid loopback JWT configuration")
        if jwks_url is not None and (
            urlsplit(jwks_url).scheme != "https" or urlsplit(issuer).scheme != "https"
        ):
            raise ValueError("OIDC issuer and JWKS URLs require HTTPS")
        self.issuer = issuer
        self.audience = audience
        self.workspace = workspace
        self.local_key = local_key
        self.cognito = cognito
        self.directory = directory
        self.jwks = jwt.PyJWKClient(jwks_url, timeout=3, lifespan=300) if jwks_url else None

    def _claims(self, authorization: str | None, client_ip: str | None) -> dict[str, Any]:
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token or len(token) > 8192:
            raise ServiceError("unauthorized", "a valid bearer token is required", 401)
        if self.local_key is not None:
            try:
                if client_ip is None or not ip_address(client_ip).is_loopback:
                    raise ValueError("outside loopback")
            except ValueError:
                raise ServiceError("forbidden", "local credentials require loopback", 403) from None
        try:
            if self.jwks:
                key = self.jwks.get_signing_key_from_jwt(token).key
                algorithm = "RS256"
            else:
                key = self.local_key
                algorithm = "HS256"
            expected = ["exp", "iss", "sub"]
            expected += ["client_id", "token_use"] if self.cognito else ["aud", "workspace"]
            claims = jwt.decode(
                token,
                key,
                algorithms=[algorithm],
                issuer=self.issuer,
                audience=None if self.cognito else self.audience,
                options={"require": expected, "verify_aud": not self.cognito},
            )
        except jwt.PyJWTError:
            raise ServiceError("unauthorized", "invalid or expired bearer token", 401) from None
        if self.cognito and (
            claims["token_use"] != "access" or claims["client_id"] != self.audience
        ):
            raise ServiceError("unauthorized", "invalid access token or client binding", 401)
        subject = claims["sub"]
        if not isinstance(subject, str) or not subject:
            raise ServiceError("unauthorized", "invalid bearer token subject", 401)
        return claims

    def oauth_claims(self, authorization: str | None, client_ip: str | None) -> dict[str, Any]:
        claims = self._claims(authorization, client_ip)
        scope = claims.get("scope")
        if not isinstance(scope, str) or "openid" not in scope.split():
            raise ServiceError("unauthorized", "an OAuth access token is required", 401)
        return claims

    def account(self, authorization: str | None, client_ip: str | None) -> Account:
        if self.directory is None:
            raise ServiceError("unavailable", "account directory is unavailable", 503)
        return self.directory.signed_in(self.oauth_claims(authorization, client_ip))

    def authenticate(self, authorization: str | None, client_ip: str | None) -> str:
        if self.directory is not None:
            account = self.account(authorization, client_ip)
            if not account.can_access:
                raise ServiceError(
                    "approval_required", "current workspace approval is required", 403
                )
            return str(account.subject)
        claims = self._claims(authorization, client_ip)
        groups = claims.get("cognito:groups", [])
        allowed = (
            isinstance(groups, list) and self.workspace in groups
            if self.cognito
            else claims["workspace"] == self.workspace
        )
        if not allowed:
            raise ServiceError("forbidden", "token is outside this workspace", 403)
        return str(claims["sub"])


def mint(
    key: str, *, workspace: str = "local", expires: int = 900, audience: str = LOCAL_AUDIENCE
) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": LOCAL_ISSUER,
            "aud": audience,
            "sub": "local-operator",
            "workspace": workspace,
            "iat": now,
            "exp": now + timedelta(seconds=expires),
        },
        key,
        algorithm="HS256",
    )
