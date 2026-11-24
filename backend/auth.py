"""JWT verification for one authorized workspace."""

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from urllib.parse import urlsplit

import jwt

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
    ) -> None:
        if not issuer or not audience or not workspace or bool(local_key) == bool(jwks_url):
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
        self.jwks = jwt.PyJWKClient(jwks_url, timeout=3, lifespan=300) if jwks_url else None

    def authenticate(self, authorization: str | None, client_ip: str | None) -> str:
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
            claims = jwt.decode(
                token,
                key,
                algorithms=[algorithm],
                issuer=self.issuer,
                audience=self.audience,
                options={"require": ["exp", "iss", "aud", "sub", "workspace"]},
            )
        except jwt.PyJWTError:
            raise ServiceError("unauthorized", "invalid or expired bearer token", 401) from None
        if claims["workspace"] != self.workspace:
            raise ServiceError("forbidden", "token is outside this workspace", 403)
        subject = claims["sub"]
        if not isinstance(subject, str) or not subject:
            raise ServiceError("unauthorized", "invalid bearer token subject", 401)
        return subject


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
