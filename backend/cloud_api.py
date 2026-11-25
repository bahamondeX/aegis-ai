"""Standalone hosted API. Authenticate Cognito access tokens before relaying to AgentCore."""

import hashlib
import json
import logging
import os
import re
from collections.abc import Callable
from functools import cache
from time import monotonic
from urllib.parse import unquote, urlsplit
from uuid import UUID

import anyio
import boto3
import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.background import BackgroundTask
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.api import create_app
from backend.auth import Auth
from backend.cloud_reader import pinned_reader
from backend.identity import cloud_directory
from backend.identity_routes import install_identity
from backend.investigations.contracts import CancelRequest
from backend.investigations.contracts import Request as Investigation
from backend.models import ServiceError
from backend.reader import SnapshotReader
from backend.v2_catalog import CatalogReader
from backend.v2_network import NetworkContextReader
from backend.v2_series import RiskSeriesReader
from infra.settings import SDK_CONFIG, Settings
from pipelines.bronze import S3Bronze
from pipelines.io import DataError

PREFIX = "/api/aegis"
KEY = re.compile(r"[A-Za-z0-9._-]{16,128}")
READS = re.compile(
    r"/v1/(?:coverage|cves(?:/CVE-\d{4}-\d{4,24})?|kpis|graph|map|evidence/[a-f0-9]{64})"
)
ACCOUNT = re.compile(r"/v1/(?:account|admin/users(?:/[\w@.+-]{1,128}/audit)?)")
ADMIN_CHANGE = re.compile(r"/v1/admin/users/[\w@.+-]{1,128}")
CANCEL = re.compile(r"/v1/investigations/[a-f0-9-]{36}/cancel")
LOG = logging.getLogger(__name__)


def runtime_url(value: str, settings: Settings) -> str:
    target = urlsplit(value)
    identifier = settings.project.replace("-", "_") + "_investigations"
    arn = (
        rf"arn:aws:bedrock-agentcore:{settings.region}:{settings.account}:runtime/"
        rf"{identifier}-[A-Za-z0-9]+"
    )
    if (
        target.scheme != "https"
        or target.netloc != f"bedrock-agentcore.{settings.region}.amazonaws.com"
        or not re.fullmatch(rf"/runtimes/{arn}/invocations", unquote(target.path))
        or target.query != "qualifier=DEFAULT"
        or target.fragment
    ):
        raise DataError("expected the approved project AgentCore DEFAULT endpoint")
    return value


class GatewayPaths:
    """Expose only the shared frontend API routes and local adapter readiness."""

    def __init__(self, app: ASGIApp, v2_reads: frozenset[str] = frozenset()) -> None:
        self.app = app
        self.v2_reads = v2_reads

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        method = scope["method"]
        if path == "/ready" and method == "GET":
            await Response(status_code=204)(scope, receive, send)
            return
        route = path.removeprefix(PREFIX)
        read = READS.fullmatch(route) or ACCOUNT.fullmatch(route) or route in self.v2_reads
        allowed = (method == "GET" and read) or (
            method == "POST"
            and (
                route in {"/v1/investigations", "/v1/account/logout"}
                or CANCEL.fullmatch(route)
                or ADMIN_CHANGE.fullmatch(route)
            )
        )
        if not path.startswith(PREFIX + "/") or not allowed:
            await Response(status_code=404)(scope, receive, send)
            return

        async def no_cache(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                if not any(key.lower() == b"cache-control" for key, _ in headers):
                    headers.append((b"cache-control", b"no-store"))
            await send(message)

        await self.app({**scope, "path": route}, receive, no_cache)


def gateway(
    reader: SnapshotReader | Callable[[], SnapshotReader],
    auth: Auth,
    upstream: str,
    client: httpx.AsyncClient,
    *,
    network: Callable[[], NetworkContextReader] | None = None,
    catalog: Callable[[], CatalogReader] | None = None,
    series: Callable[[], RiskSeriesReader] | None = None,
) -> FastAPI:
    app = create_app(reader, auth, network=network, catalog=catalog, series=series)
    loaders = (("/v2/network", network), ("/v2/catalog", catalog), ("/v2/analytics/epss", series))
    reads = frozenset(path for path, loader in loaders if loader)
    app.add_middleware(GatewayPaths, v2_reads=reads)
    install_identity(app, auth)

    async def relay(request: Request, payload: Investigation | CancelRequest) -> Response:
        bearer = request.headers.get("authorization", "")
        await anyio.to_thread.run_sync(
            auth.authenticate, bearer, request.client.host if request.client else None
        )
        if isinstance(payload, Investigation):
            snapshot = await anyio.to_thread.run_sync(reader) if callable(reader) else reader
            if payload.snapshot_id != snapshot.snapshot:
                raise ServiceError("snapshot_mismatch", "select the pinned release", 409)
        key = request.headers.get("idempotency-key", "")
        cursor = request.headers.get("last-event-id", "0")
        if not KEY.fullmatch(key) or not re.fullmatch(r"[0-9]{1,3}", cursor):
            raise ServiceError("invalid_replay", "invalid investigation key or sequence", 422)
        cancel = isinstance(payload, CancelRequest)
        headers = {
            "Authorization": bearer,
            "Accept": "application/json" if cancel else "text/event-stream",
            "Idempotency-Key": key,
            "Last-Event-ID": cursor,
            "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": hashlib.sha256(
                (bearer + key).encode()
            ).hexdigest(),
        }
        sent = monotonic()
        try:
            response = await client.send(
                client.build_request(
                    "POST", upstream, json=payload.model_dump(mode="json"), headers=headers
                ),
                stream=True,
            )
        except httpx.HTTPError as error:
            raise ServiceError(
                "runtime_unavailable", "investigation transport failed", 502
            ) from error
        if response.status_code != 200:
            await response.aclose()
            known = {401, 403, 404, 409, 422, 429, 503}
            status = response.status_code if response.status_code in known else 502
            raise ServiceError(
                "runtime_rejected", "the investigation runtime rejected the request", status
            )
        expected = "application/json" if cancel else "text/event-stream"
        if response.headers.get("content-type", "").split(";")[0] != expected:
            await response.aclose()
            raise ServiceError("runtime_protocol", "unexpected investigation response", 502)

        if cancel:
            try:
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > 4096:
                        raise ServiceError(
                            "runtime_protocol", "unexpected cancellation response", 502
                        )
            finally:
                await response.aclose()
            try:
                result = json.loads(content)
                if result["investigation_id"] != str(payload.investigation_id) or result[
                    "status"
                ] not in {
                    "running",
                    "completed",
                    "failed",
                    "interrupted",
                    "cancelled",
                }:
                    raise ValueError()
            except (ValueError, KeyError, TypeError) as error:
                raise ServiceError(
                    "runtime_protocol", "unexpected cancellation response", 502
                ) from error
            return JSONResponse(
                {"investigation_id": result["investigation_id"], "status": result["status"]}
            )

        async def events():
            headers_ms = round((monotonic() - sent) * 1000, 2)
            first = None
            try:
                with anyio.fail_after(60):
                    async for chunk in response.aiter_bytes():
                        first = first or monotonic()
                        yield chunk
            except (TimeoutError, httpx.HTTPError):
                LOG.warning("Investigation upstream stream closed before transport completion")
            finally:
                await response.aclose()
                LOG.info(
                    "agentcore_transport headers_ms=%.2f first_payload_ms=%s relay_total_ms=%.2f",
                    headers_ms,
                    round((first - sent) * 1000, 2) if first else None,
                    (monotonic() - sent) * 1000,
                )

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
            background=BackgroundTask(response.aclose),
        )

    @app.post("/v1/investigations")
    async def investigate(request: Request, payload: Investigation) -> Response:
        return await relay(request, payload)

    @app.post("/v1/investigations/{investigation_id}/cancel")
    async def cancel(request: Request, investigation_id: UUID) -> Response:
        return await relay(
            request, CancelRequest(action="cancel", investigation_id=investigation_id)
        )

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    LOG.info("Hosted API starting")
    env = os.environ.copy()
    settings = Settings.load(offline=True, environment=env)
    if env.get("AWS_REGION") != settings.region or settings.account == "000000000000":
        raise DataError("API region and project must agree")
    upstream = runtime_url(env["AEGIS_RUNTIME_URL"], settings)
    issuer = env["AEGIS_OIDC_ISSUER"]
    if not re.fullmatch(
        rf"https://cognito-idp\.{settings.region}\.amazonaws.com/{settings.region}_[A-Za-z0-9]+",
        issuer,
    ):
        raise DataError("expected a regional Cognito issuer")
    session = boto3.Session(region_name=settings.region)
    auth = Auth(
        issuer=issuer,
        audience=env["AEGIS_OIDC_AUDIENCE"],
        workspace=settings.project,
        jwks_url=f"{issuer}/.well-known/jwks.json",
        cognito=True,
        directory=cloud_directory(session, env, settings.account, SDK_CONFIG),
    )

    @cache
    def load_snapshot() -> SnapshotReader:
        try:
            if (
                session.client("sts", config=SDK_CONFIG).get_caller_identity()["Account"]
                != settings.account
            ):
                raise DataError("API STS account does not match the project")
            current = pinned_reader(session, settings, env)
        except Exception as error:
            LOG.error("Hosted release initialization failed: %s", type(error).__name__)
            raise ServiceError(
                "release_unavailable", "the pinned release is unavailable", 503
            ) from error
        LOG.info("Hosted API resolved pinned release %s", current.snapshot)
        return current

    client = httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=httpx.Timeout(12))
    network_release = env.get("AEGIS_V2_NETWORK_RELEASE")
    catalog_component = env.get("AEGIS_V2_CATALOG_COMPONENT")
    catalog_release = env.get("AEGIS_V2_CATALOG_RELEASE")
    history_campaign = env.get("AEGIS_V2_HISTORY_CAMPAIGN")
    history_release = env.get("AEGIS_V2_HISTORY_RELEASE")
    if bool(catalog_component) != bool(catalog_release):
        raise DataError("hosted catalog requires both the component and serving release digests")
    if bool(history_campaign) != bool(history_release):
        raise DataError("hosted EPSS history requires both the campaign and release digests")

    @cache
    def bronze() -> S3Bronze:
        load_snapshot()
        return S3Bronze(
            session.client("s3", config=SDK_CONFIG),
            env["AEGIS_LAKE_BUCKET"],
            settings.account,
            env["AEGIS_LAKE_KMS_ARN"],
        )

    @cache
    def load_network() -> NetworkContextReader:
        if not network_release:
            raise ServiceError("release_unavailable", "Network context is unavailable", 503)
        try:
            return NetworkContextReader.load(bronze(), network_release)
        except Exception as error:
            LOG.error("Network release initialization failed: %s", type(error).__name__)
            raise ServiceError(
                "release_unavailable", "The pinned network release is unavailable", 503
            ) from error

    @cache
    def load_catalog() -> CatalogReader:
        if not catalog_release or not catalog_component:
            raise ServiceError("release_unavailable", "The catalog release is unavailable", 503)
        try:
            return CatalogReader(bronze(), catalog_component, catalog_release)
        except Exception as error:
            LOG.error("Catalog release initialization failed: %s", type(error).__name__)
            raise ServiceError(
                "release_unavailable", "The pinned catalog release is unavailable", 503
            ) from error

    @cache
    def load_series() -> RiskSeriesReader:
        if not history_campaign or not history_release:
            raise ServiceError("release_unavailable", "The EPSS series is unavailable", 503)
        try:
            return RiskSeriesReader(bronze(), history_campaign, history_release)
        except Exception as error:
            LOG.error("EPSS release initialization failed: %s", type(error).__name__)
            raise ServiceError(
                "release_unavailable", "The pinned EPSS release is unavailable", 503
            ) from error

    uvicorn.run(
        gateway(
            load_snapshot,
            auth,
            upstream,
            client,
            network=load_network if network_release else None,
            catalog=load_catalog if catalog_release else None,
            series=load_series if history_release else None,
        ),
        host="0.0.0.0",
        port=8080,
        access_log=False,
    )


if __name__ == "__main__":
    main()
