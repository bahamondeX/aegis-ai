"""Same-origin account and administrator operations for the hosted API."""

import logging
from hashlib import sha256
from typing import Annotated

from fastapi import Depends, FastAPI, Path, Request, Response
from pydantic import BaseModel

from backend.auth import Auth
from backend.identity import Account, Audit, Change, Status
from backend.models import ServiceError

LOG = logging.getLogger(__name__)
Username = Annotated[str, Path(pattern=r"^[\w@.+-]{1,128}$")]


class UserListing(BaseModel):
    total: int
    pending: int
    approved: int
    suspended: int
    users: list[Account]


def install_identity(app: FastAPI, auth: Auth) -> None:
    directory = auth.directory
    if directory is None:
        return

    def signed_in(request: Request) -> Account:
        return auth.account(request.headers.get("Authorization"), None)

    def administrator(actor: Annotated[Account, Depends(signed_in)]) -> Account:
        if not actor.administrator or not actor.can_access:
            raise ServiceError("admin_required", "administrator access is required", 403)
        return actor

    @app.get("/v1/account")
    def account(actor: Annotated[Account, Depends(signed_in)]) -> Account:
        return actor

    @app.post("/v1/account/logout", status_code=204)
    def logout(request: Request) -> Response:
        directory.logout(auth.oauth_claims(request.headers.get("Authorization"), None))
        return Response(status_code=204)

    @app.get("/v1/admin/users", dependencies=[Depends(administrator)])
    def users() -> UserListing:
        registered = directory.users()
        return UserListing(
            total=len(registered),
            pending=sum(user.status == Status.PENDING for user in registered),
            approved=sum(user.status == Status.APPROVED for user in registered),
            suspended=sum(user.status == Status.SUSPENDED for user in registered),
            users=registered,
        )

    @app.get("/v1/admin/users/{username}/audit", dependencies=[Depends(administrator)])
    def audit(username: Username) -> list[Audit]:
        return directory.audit(username)

    @app.post("/v1/admin/users/{username}")
    def update(
        username: Username, change: Change, actor: Annotated[Account, Depends(administrator)]
    ) -> Account:
        try:
            return directory.change(actor, username, change)
        except ServiceError as error:
            LOG.warning(
                "iam_action actor=%s target_username_sha256=%s action=%s outcome=%s",
                actor.subject,
                sha256(username.encode()).hexdigest(),
                change.action,
                error.code,
            )
            raise
