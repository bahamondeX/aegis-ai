"""Prepare, authorize and execute digest-pinned EPSS history windows in AWS."""

import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from infra.settings import SDK_CONFIG, Settings
from pipelines.bronze import PREFIX, S3Bronze, artifact, ensure, put_record, record
from pipelines.bronze_migrate import verified_lake
from pipelines.config import project_environment
from pipelines.epss_bronze import (
    ATTEMPTS,
    PARQUET_LIMIT,
    PLAN_DATES,
    archive_members,
    build_plan,
    campaign_key,
    day_key,
    dispatch_key,
    plan_id,
    plan_key,
    verified_date,
)
from pipelines.io import DataError, write_json
from scripts.verify_v2_canary import INVOKE_CONFIG, report_metrics

CONCURRENCY = 4
GIB = 1024**3
AWS_SECONDS_PER_ATTEMPT = 125  # 120 second timeout plus a cold-start allowance.


def scope(env: dict[str, str]) -> Settings:
    settings = Settings.load(environment=env)
    if (settings.account[-4:], settings.region, settings.profile, settings.project) != (
        "6271",
        "us-east-1",
        "default",
        "aegis-dev",
    ):
        raise DataError("EPSS campaign is outside the approved AWS scope")
    return settings


def prepare(store: S3Bronze, tree_file: Path, expected_initial: int = 44) -> dict:
    tree = json.loads(tree_file.read_bytes())
    ref = artifact("epss", "manifests", tree_file)
    members = archive_members(tree)
    pages = store.client.get_paginator("list_objects_v2").paginate(
        Bucket=store.bucket,
        ExpectedBucketOwner=store.owner,
        Prefix=f"{PREFIX}/manifests/epss-dates/",
        PaginationConfig={"MaxItems": 3000},
    )
    observed = {row["Key"] for page in pages for row in page.get("Contents", [])}
    existing = {
        day
        for day, row in members.items()
        if day_key(day, row["sha"]) in observed and verified_date(store, day, row["sha"])
    }
    if len(existing) < expected_initial:
        raise DataError("official archive and committed canary dates differ")

    start = date.fromisoformat(min(members))
    end = date.fromisoformat(max(members))
    windows, bodies = {}, {}
    raw_bytes = 0
    maximum_parquet = 0
    for offset in range(0, (end - start).days + 1, PLAN_DATES):
        first = start + timedelta(days=offset)
        last = min(end, first + timedelta(days=PLAN_DATES - 1))
        plan = build_plan(tree, first, last, ref)
        if not plan["members"]:
            continue
        digest = plan_id(plan)
        bodies[digest] = plan
        pending = {
            day: min(PARQUET_LIMIT, max(512 * 1024, row["size"] * 3))
            for day, row in plan["members"].items()
            if day not in existing
        }
        if pending:
            windows[digest] = pending
            maximum_parquet += sum(pending.values())
            raw_bytes += sum(plan["members"][day]["size"] for day in pending)
    spec = {
        "schema_version": 1,
        "tree": tree["sha"],
        "official_days": len(members),
        "archive_absent_days": (end - start).days + 1 - len(members),
        "initial_verified_days": sorted(existing),
        "raw_bytes": raw_bytes,
        "max_normalized_bytes": maximum_parquet,
        "concurrency": CONCURRENCY,
        "max_attempts_per_day": ATTEMPTS,
        "windows": windows,
        "all_windows": sorted(bodies),
    }
    return {"campaign": plan_id(spec), "spec": spec, "plans": bodies}


def authorized(env: dict[str, str], settings: Settings, bundle: dict) -> Decimal:
    spec = bundle["spec"]
    identity = bundle["campaign"]
    windows = spec["windows"]
    source_bytes = 0
    output_bytes = 0
    days = 0
    verified = set(spec["initial_verified_days"])
    plans = bundle["plans"]
    seen: set[str] = set()
    for digest, plan in plans.items():
        subset = windows.get(digest, {})
        if (
            plan_id(plan) != digest
            or plan["tree"] != spec["tree"]
            or len(plan["members"]) > PLAN_DATES
            or subset.keys() != plan["members"].keys() - verified
            or seen.intersection(plan["members"])
        ):
            raise DataError("campaign contains an inconsistent window")
        seen.update(plan["members"])
        for day, limit in subset.items():
            if type(limit) is not int or not 0 < limit <= PARQUET_LIMIT:
                raise DataError("campaign contains an invalid normalized byte ceiling")
            source_bytes += plan["members"][day]["size"]
            output_bytes += limit
            days += 1
    if (
        identity != plan_id(spec)
        or len(verified) < 44
        or len(seen) != spec["official_days"]
        or not verified <= seen
        or not 0 < days <= 2100
        or set(plans) != set(spec["all_windows"])
        or not windows.keys() <= plans.keys()
        or spec["concurrency"] != CONCURRENCY
        or spec["max_attempts_per_day"] != ATTEMPTS
        or spec["raw_bytes"] != source_bytes
        or spec["max_normalized_bytes"] != output_bytes
        or source_bytes + output_bytes > 20 * GIB
    ):
        raise DataError("historical campaign exceeds the reviewed operation limits")
    charge = (
        days * ATTEMPTS * AWS_SECONDS_PER_ATTEMPT * Decimal("0.00001337975")
        + (source_bytes + output_bytes) * Decimal("0.023") / Decimal(10**9)
        + Decimal("0.65")  # S3, KMS, Lambda requests, image storage and log allocation.
    )
    scope_key = f"{settings.account}/{settings.region}/{settings.project}/epss-history/{identity}"
    try:
        amount = Decimal(env.get("AEGIS_V2_HISTORY_USD", ""))
        total = Decimal(env.get("AEGIS_V2_ONE_TIME_BUDGET_USD", ""))
        initial = Decimal(env.get("AEGIS_V2_MIGRATION_USD", "")) + Decimal(
            env.get("AEGIS_V2_EPSS_PLAN_USD", "")
        )
    except InvalidOperation:
        raise DataError("set the scoped historical campaign allocation") from None
    if (
        env.get("AEGIS_V2_HISTORY_APPROVAL") != scope_key
        or not all(x.is_finite() for x in (amount, total, initial))
        or not 0 < charge <= amount
        or not 0 < initial <= 2
        or not initial + amount <= total <= 15
    ):
        raise DataError("historical campaign is outside the approved V2 spending allocation")
    return charge


def publish(store: S3Bronze, bundle: dict, tree_file: Path) -> None:
    ref = artifact("epss", "manifests", tree_file)
    tree = json.loads(tree_file.read_bytes())
    for plan in bundle["plans"].values():
        expected = build_plan(
            tree, date.fromisoformat(plan["start"]), date.fromisoformat(plan["end"]), ref
        )
        if expected != plan:
            raise DataError("campaign window differs from the verified official tree")
    ensure(store, ref, tree_file)
    for digest, plan in bundle["plans"].items():
        put_record(store, plan_key(digest), plan)
    put_record(store, campaign_key(bundle["campaign"]), bundle["spec"])


def dispatch(
    store: S3Bronze,
    client: Any,
    name: str,
    campaign: str,
    plan: str,
    day: str,
    blob: str,
    attempt: int,
) -> dict:
    if receipt := verified_date(store, day, blob):
        return {"reused": True, "day": day, "scores": receipt["counts"]["valid"]}
    key = dispatch_key(campaign, plan, day, attempt)
    if attempt > 1:
        previous = record(store, dispatch_key(campaign, plan, day, attempt - 1))
        if (
            not previous
            or (datetime.now(UTC) - datetime.fromisoformat(previous["at"])).total_seconds() < 140
        ):
            raise DataError(f"previous EPSS attempt for {day} is absent or unsettled")
    event = {"campaign": campaign, "plan": plan, "date": day, "attempt": attempt}
    if not put_record(store, key, {"at": datetime.now(UTC).isoformat(), **event}, exact=False):
        raise DataError(f"EPSS invocation for {day} already reserved; inspect its outcome")
    response = client.invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        LogType="Tail",
        Payload=json.dumps(event).encode(),
    )
    with response["Payload"] as stream:
        body = json.loads(stream.read())
    result = {
        "day": day,
        "state": body.get("state"),
        "request_id": response["ResponseMetadata"]["RequestId"],
        "error": body.get("errorType"),
        "metrics": report_metrics(response["LogResult"]),
    }
    put_record(store, key.replace(".json", "-outcome.json"), result)
    receipt = verified_date(store, day, blob)
    if response.get("FunctionError") or body.get("score_date") != day or not receipt:
        raise DataError(f"EPSS invocation for {day} failed: {result['error'] or result['state']}")
    return {**result, "scores": receipt["counts"]["valid"]}


def run(
    store: S3Bronze,
    settings: Settings,
    bundle: dict,
    *,
    limit: int,
    attempt: int,
    since: str,
) -> None:
    campaign, spec = bundle["campaign"], bundle["spec"]
    if record(store, campaign_key(campaign)) != spec:
        raise DataError("historical campaign is not yet durably published")
    session, _ = settings.identity()
    name = f"{settings.project}-v2-epss"
    control = session.client("lambda", config=SDK_CONFIG)
    function = control.get_function(FunctionName=name)
    config = function["Configuration"]
    concurrency = control.get_function_concurrency(FunctionName=name)
    if (
        config["State"] != "Active"
        or config.get("LastUpdateStatus") != "Successful"
        or config["Environment"]["Variables"].get("AEGIS_V2_CAMPAIGN_ID") != campaign
        or config["Environment"]["Variables"].get("AEGIS_V2_BUCKET") != store.bucket
        or config["Environment"]["Variables"].get("AEGIS_V2_KMS") != store.kms_key
        or config["Timeout"] != 120
        or config["MemorySize"] != 1024
        or config["Architectures"] != ["arm64"]
        or concurrency.get("ReservedConcurrentExecutions") != CONCURRENCY
        or function["Tags"].get("AegisScope") != settings.project
    ):
        raise DataError("the AWS worker does not match the reviewed historical campaign")
    client = session.client("lambda", config=INVOKE_CONFIG)
    members = sorted(
        (day, digest, bundle["plans"][digest]["members"][day]["sha"])
        for digest, days in spec["windows"].items()
        for day in days
        if day >= since
    )[:limit]
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as workers:
        for offset in range(0, len(members), CONCURRENCY):
            batch = [
                workers.submit(dispatch, store, client, name, campaign, digest, day, blob, attempt)
                for day, digest, blob in members[offset : offset + CONCURRENCY]
            ]
            for task in batch:
                print(json.dumps(task.result()), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "publish", "run"))
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--tree", type=Path)
    parser.add_argument("--limit", type=int, default=32, choices=range(1, 2101), metavar="1..2100")
    parser.add_argument("--since", type=date.fromisoformat, default=date(2021, 4, 14))
    parser.add_argument("--attempt", type=int, choices=(1, 2, 3), default=1)
    args = parser.parse_args()
    env = project_environment()
    settings = scope(env)
    store = verified_lake(settings)
    if args.command in {"plan", "publish"} and not args.tree:
        parser.error("plan and publish require the official tree file")
    if args.command == "plan":
        bundle = prepare(store, args.tree)
        write_json(args.bundle, bundle)
        spec = bundle["spec"]
        print(
            json.dumps(
                {
                    "campaign": bundle["campaign"],
                    "official_days": spec["official_days"],
                    "archive_absent_days": spec["archive_absent_days"],
                    "initial_verified_days": len(spec["initial_verified_days"]),
                    "pending": sum(map(len, spec["windows"].values())),
                    "windows": len(bundle["plans"]),
                    "raw_bytes": spec["raw_bytes"],
                    "max_normalized_bytes": spec["max_normalized_bytes"],
                }
            )
        )
    else:
        bundle = json.loads(args.bundle.read_bytes())
        cost = authorized(env, settings, bundle)
        print(json.dumps({"campaign": bundle["campaign"], "bounded_usd": str(cost)}), flush=True)
        if args.command == "publish":
            publish(store, bundle, args.tree)
        else:
            run(
                store,
                settings,
                bundle,
                limit=args.limit,
                attempt=args.attempt,
                since=args.since.isoformat(),
            )


if __name__ == "__main__":
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        main()
    except ClientError as error:
        raise SystemExit(f"EPSS campaign AWS failure: {error.response['Error']['Code']}") from None
    except (BotoCoreError, DataError, ValueError, OSError, KeyError) as error:
        raise SystemExit(f"EPSS campaign failed: {error}") from None
