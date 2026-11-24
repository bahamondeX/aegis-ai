"""AgentCore HTTP application using the same authenticated graph and MCP reads."""

import argparse
import json
import os
import secrets
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID

import boto3
import uvicorn
from fastapi import FastAPI

from backend.api import create_app
from backend.auth import LOCAL_AUDIENCE, LOCAL_ISSUER, Auth
from backend.investigations.bedrock import make_selector, model_available, read_amount
from backend.investigations.service import InvestigationService
from backend.investigations.store import S3Store, SQLiteStore
from backend.reader import SnapshotReader
from infra.settings import SCAN_CUTOFF, SDK_CONFIG, Settings
from pipelines.athena import AthenaReader
from pipelines.cloud import SnapshotStore
from pipelines.config import configured_snapshot, project_environment
from pipelines.io import DataError


def runtime_app(environment: dict[str, str]) -> FastAPI:
    settings = Settings.load(offline=True, environment=environment)
    scope = f"{settings.account}/{settings.region}/{settings.project}"
    if settings.account == "000000000000" or environment.get("AWS_REGION") != settings.region:
        raise DataError("runtime region and authorized project region must agree")
    if environment.get("AEGIS_AGENTCORE_APPROVAL") != f"{scope}/agentcore":
        raise DataError("a separate scoped AgentCore approval is required")
    if environment.get("AEGIS_BEDROCK_APPROVAL") != f"{scope}/bedrock":
        raise DataError("a separate scoped Bedrock approval is required")
    read_amount(environment, "AEGIS_AGENTCORE_BUDGET_USD")
    ceiling = read_amount(environment, "AEGIS_BEDROCK_BUDGET_USD")
    in_rate = read_amount(environment, "AEGIS_BEDROCK_INPUT_USD_PER_MILLION")
    out_rate = read_amount(environment, "AEGIS_BEDROCK_OUTPUT_USD_PER_MILLION")
    auth = Auth(
        issuer=environment["AEGIS_OIDC_ISSUER"],
        audience=environment["AEGIS_OIDC_AUDIENCE"],
        workspace=environment["AEGIS_OIDC_WORKSPACE"],
        jwks_url=environment["AEGIS_OIDC_JWKS"],
        cognito=True,
    )
    session = boto3.Session(region_name=settings.region)
    if (
        session.client("sts", config=SDK_CONFIG).get_caller_identity()["Account"]
        != settings.account
    ):
        raise DataError("runtime STS account does not match the approved project")
    model_id = environment["BEDROCK_MODEL_ID"]
    model_available(session, model_id)

    snapshot = UUID(environment["AEGIS_SNAPSHOT"])
    s3 = session.client("s3", config=SDK_CONFIG)
    archive = SnapshotStore(s3, environment["AEGIS_LAKE_BUCKET"])
    release = archive.release(snapshot)
    manifest = archive.read(f"snapshots/{snapshot}/manifest.json")
    if release is None or manifest is None:
        raise DataError("runtime requires a pinned, validated cloud release")
    version = json.loads(manifest)
    if version["status"] != "ok" or UUID(version["run_id"]) != snapshot:
        raise DataError("release and snapshot manifest must agree")

    workgroup = settings.project
    athena = session.client("athena", config=SDK_CONFIG)
    group = athena.get_work_group(WorkGroup=workgroup)["WorkGroup"]
    config = group["Configuration"]
    result = config["ResultConfiguration"]
    kms = environment["AEGIS_LAKE_KMS_ARN"]
    if (
        group["State"] != "ENABLED"
        or not config.get("EnforceWorkGroupConfiguration")
        or not 0 < config.get("BytesScannedCutoffPerQuery", 0) <= SCAN_CUTOFF
        or result.get("OutputLocation") != f"s3://{environment['AEGIS_RESULTS_BUCKET']}/queries/"
        or result.get("EncryptionConfiguration") != {"EncryptionOption": "SSE_KMS", "KmsKey": kms}
    ):
        raise DataError("runtime requires the approved encrypted, scan-capped workgroup")
    reader = SnapshotReader.cloud(
        AthenaReader(athena, settings.database, workgroup),
        release,
        geo_available=version["geometry"]["status"] == "available",
    )
    store = S3Store(s3, environment["AEGIS_CHECKPOINT_BUCKET"], settings.account, kms)
    select = make_selector(session, model_id, store, ceiling, in_rate, out_rate)
    return create_app(
        reader, auth, InvestigationService(store, snapshot, select, poll=0.5), runtime=True
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke-local", action="store_true")
    parser.add_argument("--snapshot", type=UUID)
    args = parser.parse_args()
    if args.smoke_local:
        from backend.investigations.smoke import smoke

        env = project_environment()
        root = Path(env.get("AEGIS_DATA_DIR") or "data").resolve()
        reader = SnapshotReader.duckdb(root, args.snapshot or configured_snapshot(env))
        key = secrets.token_urlsafe(48)
        auth = Auth(issuer=LOCAL_ISSUER, audience=LOCAL_AUDIENCE, workspace="local", local_key=key)
        with TemporaryDirectory(prefix="aegis-runtime-") as directory:
            store = SQLiteStore(Path(directory) / "checkpoints.db")
            app = create_app(
                reader, auth, InvestigationService(store, reader.snapshot), runtime=True
            )
            smoke(app, key, reader.snapshot, runtime=True)
        return
    uvicorn.run(
        runtime_app(dict(os.environ)),
        host="0.0.0.0",
        port=8080,
        proxy_headers=False,
        access_log=False,
    )


if __name__ == "__main__":
    main()
