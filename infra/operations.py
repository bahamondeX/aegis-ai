"""Project-scoped G2 commands. Offline assembly is separate from the live diff."""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import ValidationError
from pyiceberg.catalog.glue import GlueCatalog

from infra.settings import SCAN_CUTOFF, SDK_CONFIG, SECRET_KEYS, Settings
from pipelines.athena import AthenaReader
from pipelines.cli import report
from pipelines.cloud import LATEST, Published, SnapshotStore
from pipelines.fetch import credentials
from pipelines.io import DataError, selected_snapshot, write_json
from pipelines.lakehouse import init_tables
from pipelines.publish import history_files, load_run, validate_published
from pipelines.query import Query, connect, create_views, query

ROOT = Path(__file__).resolve().parents[1]
CDK = ["npm", "exec", "--yes", "--package=aws-cdk@2.1149.0", "--", "cdk"]
APP = "uv run --locked --no-sync python -m infra.lake_stack"
CLOUD_WRITES = {
    "deploy",
    "cdk-bootstrap",
    "secrets-sync",
    "init-tables",
    "publish-local",
    "ingest-cloud",
    "verify-cloud",
    "destroy",
}


def cdk(settings: Settings, command: str, root: Path, *, offline: bool = False) -> int:
    env = {
        **os.environ,
        "AEGIS_CDK_OFFLINE": str(int(offline)),
        "CDK_DISABLE_VERSION_CHECK": "1",
        "JSII_RUNTIME_PACKAGE_CACHE": os.getenv("JSII_RUNTIME_PACKAGE_CACHE", "disabled"),
    }
    node_pin = (ROOT / ".nvmrc").read_text().strip()
    nvm_root = Path(os.getenv("NVM_DIR", str(Path.home() / ".nvm")))
    node_bin = nvm_root / "versions" / "node" / f"v{node_pin}" / "bin"
    if (node_bin / "node").is_file():
        env["PATH"] = f"{node_bin}{os.pathsep}{env.get('PATH', '')}"
    node = subprocess.run(["node", "--version"], env=env, capture_output=True, text=True)
    if node.returncode or node.stdout.strip() != f"v{node_pin}":
        raise DataError(f"CDK requires the project's Node v{node_pin} pin")
    args = [*CDK, command, "--app", APP, "--output", str(root / "cdk.out"), "--no-lookups"]
    if not offline:
        for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
            env.pop(name, None)
        env.update(
            AWS_PROFILE=settings.profile,
            AWS_REGION=settings.region,
            AWS_DEFAULT_REGION=settings.region,
        )
        args += ["--profile", settings.profile]
    if command == "bootstrap":
        policy = os.getenv("AEGIS_CDK_EXECUTION_POLICY_ARN", "")
        valid_prefixes = (
            f"arn:aws:iam::{settings.account}:policy/",
            f"arn:aws-us-gov:iam::{settings.account}:policy/",
            f"arn:aws-cn:iam::{settings.account}:policy/",
        )
        if not policy.startswith(valid_prefixes):
            raise DataError("set AEGIS_CDK_EXECUTION_POLICY_ARN to the scoped deployment policy")
        args += [
            f"aws://{settings.account}/{settings.region}",
            "--cloudformation-execution-policies",
            policy,
        ]
    elif command == "diff":
        args += ["--method", "template"]
        if offline:
            baseline = root / "empty-template.json"
            baseline.parent.mkdir(parents=True, exist_ok=True)
            write_json(baseline, {"Resources": {}})
            args += ["--template", str(baseline)]
        args += [settings.stack]
    elif command == "deploy":
        args += [settings.stack, "--require-approval", "never"]
    elif command == "destroy":
        args += [settings.stack, "--force"]
    else:
        args += [settings.stack, "--strict", "--quiet"]
    return subprocess.run(args, cwd=ROOT, env=env, check=False).returncode


def stack_outputs(session: boto3.Session, settings: Settings) -> dict[str, str]:
    stacks = session.client("cloudformation", config=SDK_CONFIG)
    stack = stacks.describe_stacks(StackName=settings.stack)["Stacks"][0]
    check_stack_owner(stack)
    outputs = {entry["OutputKey"]: entry["OutputValue"] for entry in stack["Outputs"]}
    if (
        outputs.get("GlueDatabase") != settings.database
        or outputs.get("Workgroup") != settings.project
        or outputs.get("IngestFunction") != f"{settings.project}-ingest"
        or outputs.get("ScheduleGroupName") != settings.project
        or outputs.get("ScheduleName") != f"{settings.project}-feed-refresh"
    ):
        raise DataError("stack outputs do not match the project settings")
    return outputs


def check_stack_owner(stack: dict) -> None:
    tags = {item["Key"]: item["Value"] for item in stack["Tags"]}
    if tags.get("Project") != "AEGIS" or tags.get("Environment") != "dev":
        raise DataError("existing stack does not carry the project's required ownership tags")


def check_deploy_target(session: boto3.Session, settings: Settings) -> None:
    try:
        stacks = session.client("cloudformation", config=SDK_CONFIG).describe_stacks(
            StackName=settings.stack
        )["Stacks"]
    except ClientError as error:
        if (
            error.response["Error"]["Code"] != "ValidationError"
            or "does not exist" not in (error.response["Error"]["Message"])
        ):
            raise
    else:
        check_stack_owner(stacks[0])


def preflight(session: boto3.Session, settings: Settings) -> None:
    limits = session.client("lambda", config=SDK_CONFIG).get_account_settings()
    limit = limits["AccountLimit"]
    if limit["UnreservedConcurrentExecutions"] <= 100:
        raise DataError("insufficient Lambda concurrency for one reserved execution")
    ssm = session.client("ssm", config=SDK_CONFIG)
    try:
        bootstrap = ssm.get_parameter(Name="/cdk-bootstrap/hnb659fds/version")["Parameter"]
        bootstrap_version = bootstrap["Value"]
    except ssm.exceptions.ParameterNotFound:
        bootstrap_version = "absent"
    report(
        "aws.preflight",
        account_suffix=settings.account[-4:],
        region=settings.region,
        project=settings.project,
        cdk_bootstrap_version=bootstrap_version,
        lambda_unreserved_concurrency=limit["UnreservedConcurrentExecutions"],
    )


def sync_secrets(session: boto3.Session, settings: Settings, outputs: dict[str, str]) -> int:
    source = credentials(ROOT / ".env")
    client = session.client("ssm", config=SDK_CONFIG)
    writes = 0
    for name, value in zip(SECRET_KEYS, source, strict=True):
        if value is None:
            continue
        path = f"{settings.secret_path}/{name}"
        try:
            client.put_parameter(
                Name=path,
                Value=value,
                Type="SecureString",
                KeyId=outputs["KmsKey"],
                Tags=[
                    {"Key": "Project", "Value": "AEGIS"},
                    {"Key": "Stack", "Value": settings.stack},
                    {"Key": "Environment", "Value": "dev"},
                ],
            )
        except client.exceptions.ParameterAlreadyExists:
            tags = client.list_tags_for_resource(ResourceType="Parameter", ResourceId=path)[
                "TagList"
            ]
            ownership = {tag["Key"]: tag["Value"] for tag in tags}
            if ownership.get("Project") != "AEGIS" or ownership.get("Stack") != settings.stack:
                raise DataError("existing SecureString belongs to a different project stack")
            client.put_parameter(
                Name=path,
                Value=value,
                Type="SecureString",
                KeyId=outputs["KmsKey"],
                Overwrite=True,
            )
        writes += 1
    return writes


def invoke(session: boto3.Session, function: str, event: dict) -> Published:
    client = session.client(
        "lambda",
        config=Config(connect_timeout=5, read_timeout=570, retries={"total_max_attempts": 1}),
    )
    result = client.invoke(
        FunctionName=function, InvocationType="RequestResponse", Payload=json.dumps(event).encode()
    )
    with result["Payload"] as stream:
        body = stream.read()
    if result.get("FunctionError"):
        detail = json.loads(body).get("errorMessage", "message unavailable")
        raise DataError(f"ingest Lambda returned an error: {detail[:250]}")
    if result["StatusCode"] != 200:
        raise DataError("ingest Lambda returned an unexpected HTTP status")
    return Published.model_validate_json(body).check()


def verify_infra(
    session: boto3.Session,
    settings: Settings,
    outputs: dict[str, str],
    release: Published,
    catalog: GlueCatalog,
) -> None:
    s3 = session.client("s3", config=SDK_CONFIG)
    for name in ("LakeBucket", "ResultsBucket"):
        request = {"Bucket": outputs[name], "ExpectedBucketOwner": settings.account}
        public = s3.get_public_access_block(**request)["PublicAccessBlockConfiguration"]
        encryption = s3.get_bucket_encryption(**request)["ServerSideEncryptionConfiguration"]
        rule = encryption["Rules"][0]["ApplyServerSideEncryptionByDefault"]
        if not all(public.values()) or rule["SSEAlgorithm"] != "aws:kms":
            raise DataError(f"{name}: privacy or encryption configuration mismatch")
        if rule["KMSMasterKeyID"] != outputs["KmsKey"]:
            raise DataError(f"{name}: KMS key differs from the project key")
        if s3.get_bucket_versioning(**request).get("Status") != "Enabled":
            raise DataError(f"{name}: versioning is disabled")
    latest = s3.head_object(Bucket=outputs["LakeBucket"], Key=LATEST)
    if (
        latest.get("ServerSideEncryption") != "aws:kms"
        or latest.get("SSEKMSKeyId") != outputs["KmsKey"]
    ):
        raise DataError("published release pointer differs from the KMS contract")
    workgroup = session.client("athena", config=SDK_CONFIG).get_work_group(
        WorkGroup=outputs["Workgroup"]
    )["WorkGroup"]["Configuration"]
    result_config = workgroup["ResultConfiguration"]
    if (
        workgroup["EngineVersion"]["EffectiveEngineVersion"] != "Athena engine version 3"
        or workgroup["BytesScannedCutoffPerQuery"] != SCAN_CUTOFF
        or not workgroup["EnforceWorkGroupConfiguration"]
        or result_config["EncryptionConfiguration"]
        != {"EncryptionOption": "SSE_KMS", "KmsKey": outputs["KmsKey"]}
        or result_config["OutputLocation"] != f"s3://{outputs['ResultsBucket']}/queries/"
    ):
        raise DataError("Athena workgroup enforcement differs from the stack contract")
    schedule = session.client("scheduler", config=SDK_CONFIG).get_schedule(
        GroupName=outputs["ScheduleGroupName"], Name=outputs["ScheduleName"]
    )
    if (
        schedule["ScheduleExpression"] != "rate(6 hours)"
        or schedule["State"] != "ENABLED"
        or schedule["Target"]["Arn"].rsplit(":", 1)[-1] != outputs["IngestFunction"]
        or json.loads(schedule["Target"]["Input"]) != {"action": "ingest"}
    ):
        raise DataError("the deployed six-hour ingestion schedule is not enabled or differs")
    worker = session.client("lambda", config=SDK_CONFIG)
    config = worker.get_function_configuration(FunctionName=outputs["IngestFunction"])
    concurrency = worker.get_function_concurrency(FunctionName=outputs["IngestFunction"])
    if config["Architectures"] != ["arm64"] or concurrency["ReservedConcurrentExecutions"] != 1:
        raise DataError("ingestion Lambda architecture or concurrency differs")
    for name, snapshot_id in release.snapshots.items():
        table = catalog.load_table((settings.database, name))
        if table.format_version != 2 or table.snapshot_by_id(snapshot_id) is None:
            raise DataError(f"{name}: released Iceberg v2 snapshot missing from Glue")


def normalize_times(rows: list[dict]) -> list[dict]:
    return [
        {
            key: value.replace(microsecond=value.microsecond // 1000 * 1000)
            if isinstance(value, datetime)
            else value
            for key, value in row.items()
        }
        for row in rows
    ]


def verify(
    session: boto3.Session,
    settings: Settings,
    outputs: dict[str, str],
    catalog: GlueCatalog,
    store: SnapshotStore,
    root: Path,
    snapshot: UUID | None,
) -> None:
    if (release := store.release(snapshot)) is None:
        raise DataError("no matching cloud release is available")
    verify_infra(session, settings, outputs, release, catalog)
    reader = AthenaReader(
        session.client("athena", config=SDK_CONFIG), settings.database, outputs["Workgroup"]
    )
    with TemporaryDirectory(dir=root, prefix=".cloud-verify-") as temp:
        local_root = root
        folder = selected_snapshot(root, release.run_id)
        origin = "local snapshot"
        if not folder.is_dir():
            local_root = Path(temp)
            folder = store.transfer_snapshot(local_root, release.run_id, download=True)
            create_views(folder, history_files(local_root, load_run(folder)))
            origin = "downloaded immutable Parquet and raw captures"
        manifest = validate_published(local_root, folder)
        for stats in reader.verify_counts(release, manifest["row_counts"]):
            report("athena.table", **stats)
        with connect(folder / "aegis.duckdb") as db:
            for template, options in (
                (Query.COVERAGE, {}),
                (Query.RANKING, {"limit": 1000}),
                (Query.RANKING, {"limit": 1000, "min_epss": 0.5}),
                (Query.GRAPH, {"limit": 1000}),
                (Query.GEO, {}),
                (Query.GEO, {"country_iso2": "PE"}),
            ):
                expected = normalize_times(query(db, template, **options))
                seen, stats = reader.query(release, template, **options)
                if expected != seen:
                    raise DataError(f"{template.value}: Athena results differ from DuckDB")
                report("athena.parity", template=template, rows=len(seen), **stats)
    report("cloud.verified", origin=origin, **release.model_dump(mode="json"))


def run(command: str, root: Path, snapshot: UUID | None) -> int:
    offline = command in ("synth", "diff-local")
    settings = Settings.load(offline=offline)
    if offline:
        return cdk(settings, "diff" if command == "diff-local" else command, root, offline=True)
    if command in CLOUD_WRITES:
        budget = settings.authorize()
        report("aws.budget.approved", ceiling_usd=str(budget))
    if command == "destroy" and os.getenv("AEGIS_DESTROY_APPROVAL") != settings.stack:
        raise DataError("explicit AEGIS_DESTROY_APPROVAL for the project stack is required")
    session, _ = settings.identity()
    if command == "aws-preflight":
        preflight(session, settings)
        return 0
    if command in {"diff", "deploy", "cdk-bootstrap", "destroy"}:
        if command == "destroy":
            stack_outputs(session, settings)
        if command == "deploy":
            preflight(session, settings)
            check_deploy_target(session, settings)
            diff = cdk(settings, "diff", root)
            if diff:
                return diff
        return cdk(settings, command.removeprefix("cdk-"), root)
    outputs = stack_outputs(session, settings)
    if command == "secrets-sync":
        report("ssm.sync", parameters_written=sync_secrets(session, settings, outputs))
        return 0
    # Use this command's already verified STS session for both Glue and
    # PyArrow's S3 filesystem. The latter has its own credential chain.
    credentials_ = session.get_credentials().get_frozen_credentials()
    catalog = GlueCatalog(
        "aegis",
        client=session.client("glue", config=SDK_CONFIG),
        **{
            "s3.region": settings.region,
            "s3.connect-timeout": "5",
            "s3.request-timeout": "30",
            "s3.access-key-id": credentials_.access_key,
            "s3.secret-access-key": credentials_.secret_key,
            "s3.session-token": credentials_.token,
        },
    )
    bucket = outputs["LakeBucket"]
    if command == "init-tables":
        tables = init_tables(catalog, settings.database, f"s3://{bucket}/iceberg")
        report("iceberg.initialized", table_count=len(tables), format_version=2)
        return 0
    store = SnapshotStore(session.client("s3", config=SDK_CONFIG), bucket)
    if command == "verify-cloud":
        root.mkdir(parents=True, exist_ok=True)
        verify(session, settings, outputs, catalog, store, root, snapshot)
        return 0
    event = {"action": "ingest"}
    if command == "publish-local":
        folder = selected_snapshot(root, snapshot)
        manifest = validate_published(root, folder)
        if manifest["status"] != "ok":
            raise DataError("local snapshot is incomplete")
        store.transfer_snapshot(root, UUID(folder.name), download=False)
        event = {"action": "publish", "run_id": folder.name}
    release = invoke(session, outputs["IngestFunction"], event)
    report("cloud.ingested", **release.model_dump(mode="json"))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS lakehouse operations")
    parser.add_argument(
        "command", choices=sorted(CLOUD_WRITES | {"synth", "diff-local", "diff", "aws-preflight"})
    )
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--snapshot", type=UUID)
    args = parser.parse_args()
    try:
        return run(args.command, args.data_dir.resolve(), args.snapshot)
    except (DataError, ValidationError, FileNotFoundError) as error:
        report(
            "cloud.error",
            error=str(error) if isinstance(error, DataError) else type(error).__name__,
        )
    except ClientError as error:
        report("cloud.error", operation=error.operation_name, code=error.response["Error"]["Code"])
    except BotoCoreError as error:
        report("cloud.error", error=type(error).__name__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
