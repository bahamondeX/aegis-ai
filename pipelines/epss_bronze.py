"""Process one official EPSS archive member per bounded V2 attempt."""

import argparse
import csv
import json
import os
import re
import resource
import tempfile
import time
from dataclasses import asdict
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import boto3
import httpx

from infra.settings import SDK_CONFIG, Settings
from pipelines.bronze import (
    PREFIX,
    BronzeStore,
    LocalBronze,
    ObjectRef,
    S3Bronze,
    artifact,
    ensure,
    put_record,
    record,
)
from pipelines.bulk_archive import transfer
from pipelines.bulk_epss import (
    ARCHIVE_INDEX,
    ARCHIVE_MEMBER,
    ARCHIVE_URI,
    FIRST_DAY,
    git_blob_sha1,
    normalize,
)
from pipelines.config import project_environment
from pipelines.fetch import LICENSES
from pipelines.io import DataError, digest

SOURCE_LIMIT = 16 * 1024**2
PARQUET_LIMIT = 64 * 1024**2
PLAN_DATES = 32
ATTEMPTS = 3
HEX = re.compile(r"[a-f0-9]{64}")
GIT_HEX = re.compile(r"[a-f0-9]{40}")


def archive_members(tree: dict) -> dict[str, dict]:
    if tree.get("truncated") is not False or not GIT_HEX.fullmatch(tree["sha"]):
        raise DataError("official EPSS archive tree is incomplete or malformed")
    entries = {}
    for item in tree["tree"]:
        if match := ARCHIVE_MEMBER.fullmatch(item["path"]):
            day = date.fromisoformat(match[2])
            if (
                day.year != int(match[1])
                or item["type"] != "blob"
                or match[2] in entries
                or not GIT_HEX.fullmatch(item["sha"])
                or not 0 < item["size"] <= SOURCE_LIMIT
            ):
                raise DataError("invalid or conflicting EPSS archive member")
            entries[match[2]] = {key: item[key] for key in ("path", "size", "sha")}
    if not entries or min(entries) != FIRST_DAY.isoformat():
        raise DataError("official EPSS archive omits its earliest known day")
    return entries


def plan_id(value: dict) -> str:
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def plan_key(identity: str) -> str:
    if not HEX.fullmatch(identity):
        raise DataError("invalid V2 plan digest")
    return f"{PREFIX}/manifests/epss-plans/{identity}.json"


def build_plan(tree: dict, start: date, end: date, tree_ref: ObjectRef) -> dict:
    if not FIRST_DAY <= start <= end or (end - start).days >= PLAN_DATES:
        raise DataError("choose an EPSS window of at most 32 calendar days")
    entries = archive_members(tree)
    if end.isoformat() > max(entries):
        raise DataError("EPSS plan extends beyond the observed archive index")
    chosen = {
        day: info
        for day, info in sorted(entries.items())
        if start.isoformat() <= day <= end.isoformat()
    }
    return {
        "schema_version": 1,
        "upstream": ARCHIVE_INDEX,
        "tree": tree["sha"],
        "tree_object": asdict(tree_ref),
        "start": start.isoformat(),
        "end": end.isoformat(),
        "members": chosen,
        "available_days": len(chosen),
        "absent_days": (end - start).days + 1 - len(chosen),
        "source_bytes": sum(entry["size"] for entry in chosen.values()),
        "max_attempts_per_day": ATTEMPTS,
    }


def stage_plan(store: BronzeStore, tree: Path, start: date, end: date) -> tuple[str, dict]:
    ref = artifact("epss", "manifests", tree)
    value = build_plan(json.loads(tree.read_bytes()), start, end, ref)
    identity = plan_id(value)
    ensure(store, ref, tree)
    put_record(store, plan_key(identity), value)
    return identity, value


def day_key(day: str, blob: str) -> str:
    if date.fromisoformat(day).isoformat() != day or not GIT_HEX.fullmatch(blob):
        raise DataError("invalid EPSS day or source revision")
    return f"{PREFIX}/manifests/epss-dates/{day}/{blob}.json"


def verified_date(store: BronzeStore, day: str, blob: str) -> dict | None:
    value = record(store, day_key(day, blob))
    if value is None:
        return None
    if value["score_date"] != day or value["upstream_git_blob_sha1"] != blob:
        raise DataError("EPSS date receipt differs from its identity")
    for field in ("raw_object", "normalized_object"):
        ref = ObjectRef(**value[field])
        if store.inspect(ref.key) != ref:
            raise DataError("EPSS date receipt points to a missing or altered artifact")
    return value


def commit_date(store: BronzeStore, value: dict) -> dict:
    day, blob = value["score_date"], value["upstream_git_blob_sha1"]
    key = day_key(day, blob)
    put_record(store, key, value, exact=False)
    current = verified_date(store, day, blob)
    if current is None or (
        current["raw_object"] != value["raw_object"]
        or current["normalized_object"] != value["normalized_object"]
    ):
        raise DataError("EPSS date revision has incompatible committed artifacts")
    return current


def run_date(
    store: BronzeStore,
    client: httpx.Client,
    identity: str,
    day: date,
    attempt: int,
) -> dict:
    date_text = day.isoformat()
    if type(attempt) is not int or not 1 <= attempt <= ATTEMPTS:
        raise DataError("EPSS attempt is outside its durable budget")
    plan = record(store, plan_key(identity))
    if plan is None or plan_id(plan) != identity or date_text not in plan["members"]:
        raise DataError("EPSS date is outside its committed plan")
    entry = plan["members"][date_text]
    if (
        entry["path"] != f"{day.year}/epss_scores-{date_text}.csv.gz"
        or not GIT_HEX.fullmatch(entry["sha"])
        or not 0 < entry["size"] <= SOURCE_LIMIT
    ):
        raise DataError("EPSS plan member is invalid")
    blob = entry["sha"]
    if current := verified_date(store, date_text, blob):
        return {**current, "state": "committed", "reused": True}
    attempt_dir = f"{PREFIX}/manifests/epss-jobs/{identity}/{date_text}/{attempt}"
    if not put_record(
        store,
        attempt_dir + "/start.json",
        {
            "state": "running",
            "attempt": attempt,
            "max_source_bytes": entry["size"],
            "max_parquet_bytes": PARQUET_LIMIT,
        },
        exact=False,
    ):
        return {"state": "reserved", "score_date": date_text, "attempt": attempt}
    started = time.monotonic()
    uri = ARCHIVE_URI + entry["path"]
    try:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            raw, parquet = root / "official.csv.gz", root / "records.parquet"
            fetched = transfer(client, uri, raw, SOURCE_LIMIT, entry["size"])
            if git_blob_sha1(raw) != blob:
                raise DataError("upstream EPSS member differs from the pinned fingerprint")
            counts, metadata = normalize(raw, parquet, day)
            if counts["duplicate"] or counts["rejected"] or parquet.stat().st_size > PARQUET_LIMIT:
                raise DataError("EPSS input failed normalized record or size validation")
            raw_ref, _ = ensure(store, artifact("epss", "raw", raw), raw)
            parquet_ref, _ = ensure(store, artifact("epss", "normalized", parquet), parquet)
            result = commit_date(
                store,
                {
                    "schema_version": 1,
                    **metadata,
                    "license": LICENSES["epss"],
                    "score_date": date_text,
                    "upstream_git_blob_sha1": blob,
                    "uri": uri,
                    "source_tree": plan["tree"],
                    "counts": counts,
                    "download": fetched,
                    "raw_object": asdict(raw_ref),
                    "normalized_object": asdict(parquet_ref),
                },
            )
    except (DataError, OSError, ValueError, csv.Error) as error:
        put_record(
            store,
            attempt_dir + "/outcome.json",
            {
                "state": "failed",
                "failure_type": type(error).__name__,
                "seconds": round(time.monotonic() - started, 3),
            },
        )
        raise
    put_record(
        store,
        attempt_dir + "/outcome.json",
        {
            "state": "committed",
            "seconds": round(time.monotonic() - started, 3),
            "peak_rss_native": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "scratch_artifact_bytes": raw_ref.size + parquet_ref.size,
        },
    )
    return {**result, "state": "committed", "reused": False}


def handler(event: dict[str, Any], context: Any) -> dict:
    scope = os.environ["AEGIS_V2_ACCOUNT"]
    region = os.environ["AWS_REGION"]
    identity = os.environ["AEGIS_V2_PLAN_ID"]
    if (
        context.invoked_function_arn.split(":")[3:5] != [region, scope]
        or event.get("plan") != identity
    ):
        raise DataError("EPSS worker was invoked outside its reviewed scope")
    session = boto3.Session(region_name=region)
    if session.client("sts", config=SDK_CONFIG).get_caller_identity()["Account"] != scope:
        raise DataError("EPSS worker STS account is outside its reviewed scope")
    store = S3Bronze(
        session.client("s3", config=SDK_CONFIG),
        os.environ["AEGIS_V2_BUCKET"],
        scope,
        os.environ["AEGIS_V2_KMS"],
    )
    with httpx.Client(
        timeout=20, follow_redirects=True, headers={"Accept-Encoding": "identity"}
    ) as client:
        outcome = run_date(
            store, client, identity, date.fromisoformat(event["date"]), event.get("attempt", 1)
        )
    return {key: outcome[key] for key in ("state", "score_date")}


def approved_plan_store(identity: str, days: int) -> S3Bronze:
    env = project_environment()
    settings = Settings.load(environment=env)
    scope = f"{settings.account}/{settings.region}/{settings.project}/epss-plan/{identity}"
    try:
        ceiling = Decimal(env.get("AEGIS_V2_EPSS_PLAN_USD", ""))
    except InvalidOperation:
        raise DataError("set the explicitly approved V2 EPSS plan ceiling") from None
    required = Decimal("0.25") + days * ATTEMPTS * Decimal("0.002")
    if (
        env.get("AEGIS_V2_EPSS_PLAN_APPROVAL") != scope
        or not ceiling.is_finite()
        or not 0 < required <= ceiling
    ):
        raise DataError("separate approval for this EPSS digest and bounded plan is required")
    from pipelines.bronze_migrate import verified_lake

    return verified_lake(settings)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-store", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("--tree", required=True, type=Path)
    plan.add_argument("--publish", metavar="PLAN_DIGEST")
    for option in ("--start", "--end"):
        plan.add_argument(option, required=True, type=date.fromisoformat)
    run = commands.add_parser("run")
    run.add_argument("--plan", required=True)
    run.add_argument("--date", required=True, type=date.fromisoformat)
    run.add_argument("--attempt", type=int, default=1)
    args = parser.parse_args()
    if args.command == "plan":
        ref = artifact("epss", "manifests", args.tree)
        value = build_plan(json.loads(args.tree.read_bytes()), args.start, args.end, ref)
        identity = plan_id(value)
        if args.local_store and args.publish:
            parser.error("choose either local staging or approved S3 publication")
        if args.local_store:
            stage_plan(LocalBronze(args.local_store), args.tree, args.start, args.end)
        elif args.publish:
            if identity != args.publish:
                raise DataError("EPSS plan differs from its reviewed digest")
            store = approved_plan_store(identity, value["available_days"])
            ensure(store, ref, args.tree)
            put_record(store, plan_key(identity), value)
        print(json.dumps({"plan": identity, **value}))
    else:
        if args.local_store is None:
            parser.error("local execution requires --local-store")
        local_store = LocalBronze(args.local_store)
        with httpx.Client(
            timeout=20, follow_redirects=True, headers={"Accept-Encoding": "identity"}
        ) as client:
            print(json.dumps(run_date(local_store, client, args.plan, args.date, args.attempt)))


if __name__ == "__main__":
    try:
        main()
    except (DataError, OSError, ValueError, KeyError, csv.Error) as error:
        raise SystemExit(f"V2 EPSS Bronze job failed: {error}") from None
