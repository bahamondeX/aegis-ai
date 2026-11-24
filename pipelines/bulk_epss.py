"""Capture official FIRST EPSS daily files with a resumable date index."""

import argparse
import csv
import fcntl
import gzip
import hashlib
import json
import re
import shutil
import tempfile
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import duckdb
import httpx
import pyarrow as pa
import pyarrow.parquet as pq

from pipelines.bulk_archive import TransferReceipt, check_space, transfer, verify_receipt
from pipelines.bulk_vulnerabilities import RECORD_ID, read_metadata
from pipelines.config import project_environment
from pipelines.fetch import EPSS_CURRENT, LICENSES
from pipelines.io import DataError, file_digest, write_json
from schemas.sources import utc_timestamp

FIRST_DAY = date(2021, 4, 14)
FIRST_VERSIONED_DAY = date(2022, 2, 4)
DAILY_URI = "https://epss.empiricalsecurity.com/epss_scores-{}.csv.gz"
ARCHIVE_INDEX = "https://api.github.com/repos/empiricalsec/epss_scores/git/trees/main?recursive=1"
ARCHIVE_URI = "https://raw.githubusercontent.com/empiricalsec/epss_scores/refs/heads/main/"
ARCHIVE_MEMBER = re.compile(r"(\d{4})/epss_scores-(\d{4}-\d{2}-\d{2})\.csv\.gz")
HEADER = re.compile(r"#model_version:([^,]+),score_date:([^,]+)(?:,.*)?")
SCHEMA = pa.schema(
    [
        pa.field("cve_id", pa.string(), nullable=False),
        pa.field("score_date", pa.date32(), nullable=False),
        pa.field("model_version", pa.string(), nullable=False),
        pa.field("epss", pa.float64(), nullable=False),
        pa.field("percentile", pa.float64()),
    ]
)


def score_metadata(line: str, expected: date | None) -> tuple[date, str, datetime | None]:
    if match := HEADER.fullmatch(line.rstrip()):
        source_stamp = utc_timestamp(match[2])
        day = source_stamp.date()
        if expected is not None and day != expected:
            raise DataError("EPSS file does not match the requested score date")
        return day, match[1], source_stamp
    if (
        expected is not None
        and FIRST_DAY <= expected < FIRST_VERSIONED_DAY
        and line.strip() in {"cve,epss", "cve,epss,percentile"}
    ):
        return expected, "v1", None
    raise DataError("EPSS version or score date metadata is missing")


def normalize(raw: Path, path: Path, expected: date) -> tuple[dict, dict]:
    counts = dict.fromkeys(
        ("available", "downloaded", "valid", "rejected", "duplicate", "missing_percentile"), 0
    )
    seen: set[str] = set()
    temporary = path.with_suffix(".part")
    try:
        with (
            gzip.open(raw, "rt", encoding="utf-8-sig", newline="") as stream,
            pq.ParquetWriter(temporary, SCHEMA, compression="zstd") as writer,
        ):
            first = stream.readline(1024)
            day, version, source_stamp = score_metadata(first, expected)
            header = stream.readline(1024) if first.lstrip().startswith("#") else first
            has_percentile = header.strip() == "cve,epss,percentile"
            if not has_percentile and (version != "v1" or header.strip() != "cve,epss"):
                raise DataError("unexpected EPSS CSV header")
            rows: list[dict] = []
            for row in csv.reader(stream, strict=True):
                counts["downloaded"] += 1
                if counts["downloaded"] > 2_000_000:
                    raise DataError("EPSS file exceeded the record bound")
                try:
                    if len(row) != (3 if has_percentile else 2):
                        raise ValueError("unexpected EPSS column count")
                    cve, probability = row[:2]
                    epss = float(probability)
                    rank = float(row[2]) if has_percentile and row[2] else None
                    if (
                        not RECORD_ID.fullmatch(cve)
                        or not 0 <= epss <= 1
                        or (rank is not None and not 0 <= rank <= 1)
                    ):
                        raise ValueError("invalid EPSS row")
                except ValueError:
                    counts["rejected"] += 1
                    continue
                if cve in seen:
                    counts["duplicate"] += 1
                    continue
                seen.add(cve)
                counts["missing_percentile"] += rank is None
                rows.append(
                    {
                        "cve_id": cve,
                        "score_date": day,
                        "model_version": version,
                        "epss": epss,
                        "percentile": rank,
                    }
                )
                if len(rows) >= 16_384:
                    check_space(path.parent)
                    writer.write_table(pa.Table.from_pylist(rows, schema=SCHEMA))
                    rows.clear()
            if rows:
                writer.write_table(pa.Table.from_pylist(rows, schema=SCHEMA))
        if not counts["downloaded"]:
            raise DataError("empty EPSS score table")
        counts["available"], counts["valid"] = counts["downloaded"], len(seen)
        temporary.replace(path)
        return counts, {
            "score_date": day.isoformat(),
            "model_version": version,
            "published_at": source_stamp.isoformat() if source_stamp else None,
        }
    finally:
        temporary.unlink(missing_ok=True)


def date_pointer(root: Path, day: date) -> Path:
    return root / f"score_date={day}" / "current.json"


def lookup(root: Path, day: date) -> tuple[Path, dict] | None:
    pointer = date_pointer(root, day)
    if not pointer.exists():
        return None
    path = pointer.parent / json.loads(pointer.read_text())["sha256"]
    return path, json.loads((path / "receipt.json").read_text())


def stage(
    root: Path,
    day: date,
    payload: Path,
    download: TransferReceipt,
    uri: str,
    blob_sha1: str | None = None,
) -> dict:
    pointer = date_pointer(root, day)
    folder = pointer.parent / download["sha256"]
    folder.mkdir(parents=True, exist_ok=True)
    receipt_file, raw, scores = (
        folder / "receipt.json",
        folder / "payload",
        folder / "records.parquet",
    )
    if receipt_file.is_file() and verify_receipt(
        folder, receipt := json.loads(receipt_file.read_text())
    ):
        cached = True
    else:
        payload.replace(raw)
        counts, metadata = normalize(raw, scores, day)
        receipt = {
            "schema_version": 1,
            "uri": uri,
            "upstream_git_blob_sha1": blob_sha1,
            "license": LICENSES["epss"],
            **metadata,
            "raw": download,
            "normalized_bytes": scores.stat().st_size,
            "normalized_sha256": file_digest(scores),
            "counts": counts,
        }
        write_json(receipt_file, receipt)
        cached = False
    if not (receipt["counts"]["duplicate"] or receipt["counts"]["rejected"]):
        write_json(pointer, {"sha256": download["sha256"]})
    return {**receipt, "cached": cached}


def git_blob_sha1(path: Path) -> str:
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"blob {path.stat().st_size}\0".encode())
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def capture(client: httpx.Client, root: Path, day: date | None, member: dict | None = None) -> dict:
    if day and (pinned := lookup(root, day)):
        path, receipt = pinned
        if verify_receipt(path, receipt) and (
            member is None or git_blob_sha1(path / "payload") == member["sha"]
        ):
            return {**receipt, "cached": True}
    if member:
        uri = ARCHIVE_URI + member["path"]
    else:
        uri = DAILY_URI.format(day) if day else EPSS_CURRENT
    with tempfile.TemporaryDirectory(dir=root) as staging:
        raw = Path(staging) / "epss.csv.gz"
        download = transfer(client, uri, raw, 16 * 1024 * 1024, member["size"] if member else None)
        if member and git_blob_sha1(raw) != member["sha"]:
            raise DataError("EPSS archive member differs from its Git blob fingerprint")
        if day is None:
            with gzip.open(raw, "rt", encoding="utf-8-sig") as stream:
                day, _, _ = score_metadata(stream.readline(1024), None)
        return stage(root, day, raw, download, uri, member["sha"] if member else None)


def dates(start: date, end: date) -> list[date]:
    return [start + timedelta(days=day) for day in range((end - start).days + 1)]


def archive_plan(client: httpx.Client, root: Path) -> dict[date, dict]:
    tree = json.loads(read_metadata(client, ARCHIVE_INDEX, root))
    if tree.get("truncated"):
        raise DataError("official EPSS archive index is incomplete")
    entries = {}
    for item in tree["tree"]:
        if match := ARCHIVE_MEMBER.fullmatch(item["path"]):
            day = date.fromisoformat(match[2])
            if day.year != int(match[1]) or item["type"] != "blob" or day in entries:
                raise DataError("official EPSS archive index contains conflicting dates")
            entries[day] = item
    if not entries or min(entries) != FIRST_DAY:
        raise DataError("official EPSS archive index is missing its documented first date")
    archive = root / "archive-manifests"
    archive.mkdir(exist_ok=True)
    write_json(archive / (tree["sha"] + ".json"), tree)
    expected = dates(min(entries), max(entries))
    plan = {
        "observed_at": datetime.now(UTC).isoformat(),
        "upstream_manifest": ARCHIVE_INDEX,
        "tree_sha": tree["sha"],
        "first_available_day": min(entries).isoformat(),
        "latest_available_day": max(entries).isoformat(),
        "available_dates": len(entries),
        "expected_calendar_dates": len(expected),
        "missing_dates": [day.isoformat() for day in expected if day not in entries],
        "compressed_bytes": sum(item["size"] for item in entries.values()),
        "compressed_bytes_by_year": {
            year: sum(entry["size"] for day, entry in entries.items() if day.year == year)
            for year in range(min(entries).year, max(entries).year + 1)
        },
    }
    write_json(root / "archive-plan.json", plan)
    return entries


def trend(root: Path, cve_id: str, start: date, end: date) -> None:
    paths = []
    for day in dates(start, end):
        if pinned := lookup(root, day):
            paths.append(str(pinned[0] / "records.parquet"))
    if not paths:
        raise DataError("no captured dates in the requested range")
    with duckdb.connect(config={"memory_limit": "256MB", "threads": "2"}) as db:
        db.read_parquet(paths).create_view("scores")
        rows = db.execute(
            """SELECT score_date, model_version, epss, percentile,
                      CASE WHEN lag(score_date) OVER w = score_date - 1
                             AND lag(model_version) OVER w = model_version
                        THEN epss - lag(epss) OVER w
                      END AS daily_probability_change
                 FROM scores WHERE cve_id = ?
               WINDOW w AS (ORDER BY score_date) ORDER BY score_date""",
            [cve_id],
        ).fetchall()
    print(json.dumps({"cve_id": cve_id, "trend": rows}, default=str, sort_keys=True))


def summarize(
    root: Path,
    requested: list[date],
    outcomes: list[dict],
    missing: list[date],
    catalogued: set[date] | None = None,
) -> None:
    listed = set(requested) if catalogued is None else catalogued
    manifest = {
        "observed_at": datetime.now(UTC),
        "expected_score_dates": len(requested),
        "catalogued_score_dates": len(listed),
        "captured_score_dates": len(outcomes),
        "dates_absent_from_archive_index": [
            day.isoformat() for day in requested if day not in listed
        ],
        "provider_unavailable_dates": [day.isoformat() for day in missing],
        "dates_not_visited_or_unavailable": [
            day.isoformat()
            for day in requested
            if day in listed and not date_pointer(root, day).exists()
        ],
        "available_records_in_captured_files": sum(row["counts"]["available"] for row in outcomes),
        "valid_records": sum(row["counts"]["valid"] for row in outcomes),
        "rejected_records": sum(row["counts"]["rejected"] for row in outcomes),
        "duplicate_records": sum(row["counts"]["duplicate"] for row in outcomes),
        "records_without_source_percentile": sum(
            row["counts"].get("missing_percentile", 0) for row in outcomes
        ),
        "downloaded_or_cached_bytes": sum(row["raw"]["bytes"] for row in outcomes),
        "normalized_bytes": sum(row["normalized_bytes"] for row in outcomes),
        "remaining_disk_bytes": shutil.disk_usage(root).free,
        "captures": outcomes,
    }
    output = root / f"report-{requested[0]}-through-{requested[-1]}.json"
    write_json(output, manifest)
    print(json.dumps({"report": str(output), **manifest}, default=str))


def run(root: Path, start: date | None, end: date | None, limit: int, plan_only: bool) -> int:
    outcomes: list[dict] = []
    missing: list[date] = []
    with httpx.Client(
        follow_redirects=True,
        timeout=20,
        headers={"User-Agent": "AEGIS AI public archive ingestion", "Accept-Encoding": "identity"},
    ) as client:
        if plan_only:
            archive_plan(client, root)
            print((root / "archive-plan.json").read_text())
            return 0
        if start is None or end is None:
            captured = capture(client, root, None)
            summarize(root, [date.fromisoformat(captured["score_date"])], [captured], missing)
            return int(bool(captured["counts"]["duplicate"] or captured["counts"]["rejected"]))
        requested = dates(start, end)
        members = archive_plan(client, root)
        catalogued = set(requested) & members.keys()
        downloads = 0
        try:
            for day in requested:
                if day not in members:
                    missing.append(day)
                    continue
                if not date_pointer(root, day).exists():
                    if downloads >= limit:
                        continue
                    downloads += 1
                try:
                    outcomes.append(capture(client, root, day, members[day]))
                except DataError as error:
                    if str(error) not in (
                        "public archive retrieval failed with HTTP 403",
                        "public archive retrieval failed with HTTP 404",
                        "public archive retrieval failed with HTTP 410",
                    ):
                        raise
                    missing.append(day)
        finally:
            summarize(root, requested, outcomes, missing, catalogued)
    accepted = {
        date.fromisoformat(row["score_date"])
        for row in outcomes
        if not (row["counts"]["duplicate"] or row["counts"]["rejected"])
    }
    return int(accepted != catalogued)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--start", type=date.fromisoformat)
    parser.add_argument("--end", type=date.fromisoformat)
    parser.add_argument("--max-downloads", type=int, default=7, choices=range(1, 366), metavar="N")
    parser.add_argument("--trend", type=str)
    parser.add_argument("--archive-plan", action="store_true")
    args = parser.parse_args()
    if bool(args.start) != bool(args.end) or (
        args.start
        and (args.start < FIRST_DAY or not args.start <= args.end <= datetime.now(UTC).date())
    ):
        parser.error("provide an ordered published score date range from 2021-04-14")
    if args.trend and (not args.start or not RECORD_ID.fullmatch(args.trend)):
        parser.error("--trend requires a CVE and date range")
    env = project_environment()
    root = (args.root or Path(env.get("AEGIS_DATA_DIR") or "data") / "v2/epss").resolve()
    root.mkdir(parents=True, exist_ok=True)
    if args.trend:
        trend(root, args.trend, args.start, args.end)
        return 0
    with (root / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return run(root, args.start, args.end, args.max_downloads, args.archive_plan)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DataError, OSError, csv.Error, ValueError) as error:
        raise SystemExit(f"V2 EPSS capture failed: {error}") from None
