"""Verify the live, approved V2 EPSS canary using durable receipts and Lambda reports."""

import argparse
import base64
import hashlib
import json
import re
from collections import Counter
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from infra.settings import SDK_CONFIG, Settings
from pipelines.bronze import PREFIX, ObjectRef, record
from pipelines.config import project_environment
from pipelines.epss_bronze import approved_plan_store, plan_id, plan_key, verified_date
from pipelines.io import DataError, write_json

REPORT_METRICS = {
    "duration_ms": ("Duration", "ms"),
    "billed_ms": ("Billed Duration", "ms"),
    "memory_mb": ("Memory Size", "MB"),
    "max_memory_mb": ("Max Memory Used", "MB"),
    "init_ms": ("Init Duration", "ms"),
}
INVOKE_CONFIG = Config(
    connect_timeout=5,
    read_timeout=135,
    retries={"mode": "standard", "total_max_attempts": 1},
)


def report_metrics(log: str) -> dict[str, float]:
    log = base64.b64decode(log, validate=True).decode("utf-8")
    lines = [line for line in log.splitlines() if line.startswith("REPORT RequestId:")]
    if len(lines) != 1:
        raise DataError("Lambda returned no unique REPORT line")
    fields = {}
    for key, (name, unit) in REPORT_METRICS.items():
        match = re.search(rf"(?:\t| {{2,}}){name}:\s+(\d+(?:\.\d+)?)\s+{unit}\b", lines[0])
        if match:
            fields[key] = float(match[1])
    if set(REPORT_METRICS) - {"init_ms"} - fields.keys():
        raise DataError("Lambda REPORT line lacks required metrics")
    return fields


def invoke(client: Any, name: str, identity: str, day: str, evidence: Path) -> dict:
    event = {"plan": identity, "date": day, "attempt": 1}
    if evidence.exists():
        saved = json.loads(evidence.read_text())
        if saved["date"] != day or saved["plan"] != identity or saved["state"] != "committed":
            raise DataError("existing invocation evidence differs from the approved canary")
        return saved
    response = client.invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        LogType="Tail",
        Payload=json.dumps(event).encode(),
    )
    with response["Payload"] as stream:
        body = json.loads(stream.read())
    result = {
        "observed_at": datetime.now(UTC).isoformat(),
        "plan": identity,
        "date": day,
        "request_id": response["ResponseMetadata"]["RequestId"],
        "state": body.get("state"),
        "metrics": report_metrics(response["LogResult"]),
        "function_error": response.get("FunctionError"),
        "error_type": body.get("errorType"),
    }
    write_json(evidence, result)
    if (
        response.get("FunctionError")
        or body.get("score_date") != day
        or body.get("state") != "committed"
    ):
        raise DataError("Lambda canary did not commit the approved EPSS date")
    return result


def verify(approval: Path, inventory_file: Path, destination: Path, expected_image: str) -> dict:
    plan = json.loads(approval.read_text())
    identity = plan.pop("plan")
    if plan_id(plan) != identity or list(plan["members"]) != ["2026-11-20", "2026-11-21"]:
        raise DataError("unexpected reviewed canary plan")
    fresh, migrated = plan["members"]
    store = approved_plan_store(identity, len(plan["members"]))
    reads: Counter[str] = Counter()

    def count_read(model: Any, **_: Any) -> None:
        reads[model.name] += 1

    store.client.meta.events.register("after-call.s3.*", count_read)
    env = project_environment()
    settings = Settings.load(environment=env)
    if (settings.account[-4:], settings.profile, settings.region, settings.project) != (
        "6271",
        "default",
        "us-east-1",
        "aegis-dev",
    ):
        raise DataError("AWS scope differs from the reviewed canary")
    session, _ = settings.identity()
    function_name = f"{settings.project}-v2-epss"
    function = session.client("lambda", config=SDK_CONFIG).get_function(FunctionName=function_name)
    config = function["Configuration"]
    image = function["Code"]["ResolvedImageUri"]
    tags = function["Tags"]
    if (
        config["State"] != "Active"
        or config["Architectures"] != ["arm64"]
        or config["Timeout"] != 120
        or config["MemorySize"] != 1024
        or config["EphemeralStorage"]["Size"] != 2048
        or config["Environment"]["Variables"].get("AEGIS_V2_PLAN_ID") != identity
        or not image.endswith("@" + expected_image)
        or tags.get("Project") != "AEGIS"
        or tags.get("AegisScope") != settings.project
    ):
        raise DataError("deployed canary config differs from the reviewed asset")
    pinned = record(store, plan_key(identity))
    if not pinned or plan_id(pinned) != identity:
        raise DataError("remote EPSS plan is unavailable or differs")

    local_inventory = json.loads(inventory_file.read_text())
    path = f"{PREFIX}/manifests/migrations/{local_inventory['id']}/committed.json"
    migration = record(store, path)
    if not migration or (
        len(migration["objects"]) != local_inventory["objects"]
        or sum(item["size"] for item in migration["objects"]) != local_inventory["bytes"]
    ):
        raise DataError("remote Bronze migration is missing or has inconsistent totals")

    def date_receipt(day: str) -> dict | None:
        return verified_date(store, day, plan["members"][day]["sha"])

    prefix = f"{PREFIX}/manifests/epss-jobs/{identity}"
    imported = date_receipt(migrated)
    if not imported or record(store, f"{prefix}/{migrated}/1/start.json"):
        raise DataError("the expected date was not imported from the verified migration")
    if date_receipt(fresh) and not (destination / "invoke-fresh.json").is_file():
        raise DataError("fresh-canary date was already committed before this validation")
    destination.mkdir(parents=True, exist_ok=True)
    client = session.client("lambda", config=INVOKE_CONFIG)
    imported_call = invoke(
        client, function_name, identity, migrated, destination / "invoke-imported.json"
    )
    if record(store, f"{prefix}/{migrated}/1/start.json") or date_receipt(migrated) != imported:
        raise DataError("invoking the imported date modified its receipt")
    new_call = invoke(client, function_name, identity, fresh, destination / "invoke-fresh.json")
    receipt = date_receipt(fresh)
    outcome = record(store, f"{prefix}/{fresh}/1/outcome.json")
    if (
        not receipt
        or not outcome
        or outcome["state"] != "committed"
        or receipt["counts"]["rejected"]
        or receipt["counts"]["duplicate"]
        or receipt["counts"]["valid"] != receipt["counts"]["downloaded"]
    ):
        raise DataError("fresh EPSS receipt does not reconcile the official input")
    # Read one actual object version and verify its bytes, in addition to the receipt HEADs.
    ref = ObjectRef(**receipt["raw_object"])
    with store.open_object(ref) as body:
        observed = (
            hashlib.file_digest(body, "sha256").hexdigest()
            if hasattr(body, "readinto")
            else hashlib.sha256(body.read(ref.size + 1)).hexdigest()
        )
    if observed != ref.sha256:
        raise DataError("version-pinned EPSS read failed its full-byte checksum")
    replay = invoke(client, function_name, identity, fresh, destination / "invoke-replay.json")
    if (
        date_receipt(fresh) != receipt
        or record(store, f"{prefix}/{fresh}/1/outcome.json") != outcome
        or record(store, f"{prefix}/{fresh}/2/start.json")
    ):
        raise DataError("canary replay ran additional work or changed a committed object")
    calls = [imported_call, new_call, replay]
    billed_ms = sum((Decimal(str(item["metrics"]["billed_ms"])) for item in calls), Decimal(0))
    gb_seconds = billed_ms / 1000
    request_estimate = len(calls) * Decimal("0.0000002")
    estimate = (
        gb_seconds * Decimal("0.0000133334")
        + gb_seconds * Decimal("1.5") * Decimal("0.0000000309")
        + request_estimate
    )
    return {
        "state": "passed",
        "plan": identity,
        "migration_objects": len(migration["objects"]),
        "migration_bytes": local_inventory["bytes"],
        "invocations": calls,
        "lambda_invocation_count": len(calls),
        "s3_verification_calls": dict(reads),
        "fresh_records": receipt["counts"]["valid"],
        "scratch_bytes": outcome["scratch_artifact_bytes"],
        "fresh_object_sizes": [receipt[key]["size"] for key in ("raw_object", "normalized_object")],
        "fresh_version_ids": [
            receipt[key]["version_id"] for key in ("raw_object", "normalized_object")
        ],
        "raw_body_verified": True,
        "receipt_reused": True,
        "lambda_estimated_usd": str(estimate),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", args.image):
        raise DataError("expected the exact verified ECR image digest")
    result = verify(args.plan, args.inventory, args.evidence, args.image)
    write_json(args.evidence / "canary.json", result)
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except ClientError as error:
        raise SystemExit(f"V2 canary AWS error: {error.response['Error']['Code']}") from None
    except (BotoCoreError, DataError, OSError, ValueError, KeyError) as error:
        raise SystemExit(f"V2 canary verification failed: {error}") from None
