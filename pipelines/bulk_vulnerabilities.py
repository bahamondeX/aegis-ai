"""Build local, source-preserving KEV, NVD and CVE List V5 corpora."""

import argparse
import fcntl
import gzip
import json
import re
import shutil
import tempfile
import time
from collections.abc import Iterable, Iterator
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile

import duckdb
import httpx
import ijson
import pyarrow as pa
import pyarrow.parquet as pq

from pipelines.bulk_archive import (
    TRANSFER_LIMIT,
    Archive,
    TransferReceipt,
    check_space,
    transfer,
    verify_archive,
    verify_receipt,
)
from pipelines.config import project_environment
from pipelines.fetch import CISA, LICENSES
from pipelines.io import DataError, file_digest, write_json
from schemas.sources import utc_timestamp

NVD_FEED = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"
CVE_RELEASES = "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=35"
LICENSE = {
    "kev": LICENSES["cisa"],
    "nvd": LICENSES["nvd"],
    "cve": "CVE Program Terms of Use, https://www.cve.org/Legal/TermsOfUse",
}
RECORD_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
HASH = re.compile(r"[a-f0-9]{64}")
DATE = pa.timestamp("us", tz="UTC")
SCHEMA = pa.schema(
    [
        pa.field("cve_id", pa.string(), nullable=False),
        pa.field("published_at", DATE),
        pa.field("modified_at", DATE),
        pa.field("status", pa.string()),
        pa.field("has_cvss", pa.bool_()),
        pa.field("has_cwe", pa.bool_()),
        pa.field("has_cpe", pa.bool_()),
        pa.field("has_adp", pa.bool_()),
        pa.field("has_ssvc", pa.bool_()),
        pa.field("payload", pa.large_string(), nullable=False),
    ]
)


def read_metadata(client: httpx.Client, uri: str, root: Path) -> str:
    with tempfile.TemporaryDirectory(dir=root) as temporary:
        artifact = Path(temporary) / "metadata"
        transfer(client, uri, artifact, 4 * 1024 * 1024)
        return artifact.read_text(encoding="utf-8")


def nvd_archive(client: httpx.Client, root: Path, key: str) -> Archive:
    metadata_uri = NVD_FEED + key + ".meta"
    meta = dict(
        line.split(":", 1) for line in read_metadata(client, metadata_uri, root).splitlines()
    )
    date = utc_timestamp(meta["lastModifiedDate"])
    checksum = meta["sha256"].lower()
    compressed, uncompressed = int(meta["gzSize"]), int(meta["size"])
    if not HASH.fullmatch(checksum) or not 0 < compressed <= TRANSFER_LIMIT or uncompressed < 1:
        raise DataError("invalid NVD META record")
    return Archive(
        "nvd",
        key,
        NVD_FEED + key + ".json.gz",
        checksum,
        date,
        length=compressed,
        uncompressed_length=uncompressed,
        uncompressed_sha256=checksum,
        metadata_uri=metadata_uri,
    )


def cve_archives(client: httpx.Client, root: Path) -> list[Archive]:
    releases = json.loads(read_metadata(client, CVE_RELEASES, root))
    assets = [(r["tag_name"], a) for r in releases for a in r["assets"]]
    try:
        tag, baseline = max(
            (
                (tag, asset)
                for tag, asset in assets
                if re.fullmatch(r"\d{4}-\d{2}-\d{2}_all_CVEs_at_midnight(?:\.zip)+", asset["name"])
            ),
            key=lambda entry: entry[0],
        )
    except ValueError:
        raise DataError("official CVE List baseline is missing from the release manifest") from None
    day = baseline["name"][:10]
    deltas = [
        (tag, a)
        for tag, a in assets
        if re.fullmatch(day + r"_delta_CVEs_at_\d{4}Z\.zip", a["name"])
    ]
    chosen = [("baseline", tag, baseline)]
    if deltas:
        delta_tag, delta = max(deltas, key=lambda entry: entry[0])
        chosen.append(("delta", delta_tag, delta))
    result = []
    for key, tag, asset in chosen:
        checksum = (asset.get("digest") or "").removeprefix("sha256:")
        uri = asset["browser_download_url"]
        if (
            not HASH.fullmatch(checksum)
            or not uri.startswith("https://github.com/CVEProject/cvelistV5/releases/download/")
            or not 0 < asset["size"] <= TRANSFER_LIMIT
        ):
            raise DataError("CVE Program release asset lacks a trusted size, digest or origin")
        published = datetime.strptime(tag, "cve_%Y-%m-%d_%H%MZ").replace(tzinfo=UTC)
        result.append(
            Archive(
                "cve",
                key,
                uri,
                checksum,
                published,
                asset["size"],
                checksum,
                metadata_uri=CVE_RELEASES,
            )
        )
    return result


def source_records(archive: Archive, raw: Path) -> Iterator[tuple[str | None, object]]:
    if archive.source == "nvd":
        with gzip.open(raw, "rb") as stream:
            for record in ijson.items(stream, "vulnerabilities.item", use_float=True):
                yield None, record
    elif archive.source == "kev":
        catalog = json.loads(raw.read_bytes())
        for record in catalog["vulnerabilities"]:
            yield None, record
    else:
        with ZipFile(raw) as payload:
            members = payload.infolist()
            if len(members) == 1 and members[0].filename == "cves.zip":
                size = members[0].file_size
                if size > TRANSFER_LIMIT:
                    raise DataError("nested CVE List ZIP exceeds the archive size bound")
                check_space(raw.parent, size)
                with (
                    payload.open(members[0]) as inner,
                    tempfile.TemporaryFile(dir=raw.parent) as spool,
                ):
                    shutil.copyfileobj(inner, spool, length=1024 * 1024)
                    with ZipFile(spool) as nested:
                        yield from zip_records(nested)
            else:
                yield from zip_records(payload)


def zip_records(payload: ZipFile) -> Iterator[tuple[str | None, object]]:
    for item in payload.infolist():
        name = PurePosixPath(item.filename)
        if not RECORD_ID.fullmatch(name.stem) or name.suffix != ".json":
            continue
        if item.file_size > 8 * 1024 * 1024:
            yield name.stem, None
            continue
        try:
            yield name.stem, json.loads(payload.read(item))
        except (ValueError, UnicodeError):
            yield name.stem, None


def fields(archive: Archive, name: str | None, record: dict) -> tuple:
    if archive.source == "nvd":
        value = record["cve"]
        key, published, modified, status = (
            value["id"],
            value.get("published"),
            value.get("lastModified"),
            value.get("vulnStatus"),
        )
        if not isinstance(key, str) or not RECORD_ID.fullmatch(key):
            raise ValueError("invalid NVD CVE ID")
        year = int(key[4:8])
        if archive.key.isdecimal() and (
            (archive.key == "2002" and year > 2002)
            or (archive.key != "2002" and year != int(archive.key))
        ):
            raise ValueError("CVE assigned to the wrong NVD annual partition")
    elif archive.source == "cve":
        value = record["cveMetadata"]
        key, published, modified, status = (
            value["cveId"],
            value.get("datePublished"),
            value.get("dateUpdated"),
            value.get("state"),
        )
        if key != name or not isinstance(record.get("containers"), dict):
            raise ValueError("CVE ZIP member does not match its record or lacks containers")
    else:
        key, published, modified, status = record["cveID"], None, None, None
    if not isinstance(key, str) or not RECORD_ID.fullmatch(key):
        raise ValueError("invalid CVE ID")
    return key, published, modified, status


def enrichments(source: str, record: dict) -> dict[str, bool]:
    if source == "nvd":
        value = record["cve"]
        return {
            "has_cvss": any(value.get("metrics", {}).values()),
            "has_cwe": any(
                str(description.get("value", "")).startswith("CWE-")
                for weakness in value.get("weaknesses", [])
                for description in weakness.get("description", [])
            ),
            "has_cpe": bool(value.get("configurations")),
        }
    if source == "cve":
        adp = record["containers"].get("adp", [])
        return {
            "has_adp": bool(adp),
            "has_ssvc": any(
                metric.get("other", {}).get("type") == "ssvc"
                for container in adp
                for metric in container.get("metrics", [])
            ),
        }
    return {}


def normalize(archive: Archive, raw: Path, output: Path, expected: int | None) -> dict[str, int]:
    counts = dict.fromkeys(
        ("available", "downloaded", "valid", "rejected", "duplicate", "invalid_timestamps"), 0
    )
    seen: set[str] = set()
    batch: list[dict] = []
    temporary = output.with_suffix(".part")
    try:
        with pq.ParquetWriter(temporary, SCHEMA, compression="zstd") as writer:
            for name, record in source_records(archive, raw):
                counts["downloaded"] += 1
                try:
                    if not isinstance(record, dict):
                        raise ValueError("record is not a JSON object")
                    key, published, modified, status = fields(archive, name, record)
                    flags = enrichments(archive.source, record)
                except (AttributeError, KeyError, TypeError, ValueError):
                    counts["rejected"] += 1
                    continue
                if key in seen:
                    counts["duplicate"] += 1
                    continue
                seen.add(key)
                dates = []
                for stamp in (published, modified):
                    try:
                        dates.append(utc_timestamp(stamp) if stamp is not None else None)
                    except (TypeError, ValueError, AttributeError):
                        counts["invalid_timestamps"] += 1
                        dates.append(None)
                batch.append(
                    {
                        "cve_id": key,
                        "published_at": dates[0],
                        "modified_at": dates[1],
                        "status": status,
                        **flags,
                        "payload": json.dumps(record, ensure_ascii=False, separators=(",", ":")),
                    }
                )
                if len(batch) == 1024:
                    check_space(output.parent)
                    writer.write_table(pa.Table.from_pylist(batch, schema=SCHEMA))
                    batch.clear()
            if batch:
                writer.write_table(pa.Table.from_pylist(batch, schema=SCHEMA))
        counts["valid"] = len(seen)
        counts["available"] = expected if expected is not None else counts["downloaded"]
        if counts["downloaded"] != counts["available"] or not counts["downloaded"]:
            raise DataError("archive records differ from the authoritative record count")
        temporary.replace(output)
        return counts
    finally:
        temporary.unlink(missing_ok=True)


def capture(
    archive: Archive,
    root: Path,
    client: httpx.Client,
    *,
    supplied: Path | None = None,
    supplied_receipt: TransferReceipt | None = None,
    expected: int | None = None,
) -> dict:
    folder = archive.folder(root)
    folder.mkdir(parents=True, exist_ok=True)
    manifest, raw = folder / "receipt.json", folder / "payload"
    output = folder / "records.parquet"
    if manifest.is_file() and verify_receipt(folder, receipt := json.loads(manifest.read_text())):
        return {**receipt, "cached": True}
    raw_receipt_path = folder / "payload.json"
    if supplied is not None and supplied_receipt is not None:
        if not raw.is_file():
            supplied.replace(raw)
        raw_receipt = supplied_receipt
    elif raw.is_file() and raw_receipt_path.is_file():
        raw_receipt = json.loads(raw_receipt_path.read_text())
        if raw.stat().st_size != raw_receipt["bytes"] or file_digest(raw) != raw_receipt["sha256"]:
            raise DataError("cached archive differs from its local receipt")
    else:
        raw_receipt = transfer(
            client, archive.uri, raw, archive.length or TRANSFER_LIMIT, archive.length
        )
    verify_archive(archive, raw, raw_receipt["sha256"])
    write_json(raw_receipt_path, raw_receipt)
    started = time.monotonic()
    counts = normalize(archive, raw, output, expected)
    receipt = {
        "schema_version": 1,
        "archive": asdict(archive),
        "license": LICENSE[archive.source],
        "raw": raw_receipt,
        "normalized_bytes": output.stat().st_size,
        "normalized_sha256": file_digest(output),
        "normalization_seconds": round(time.monotonic() - started, 3),
        "counts": counts,
    }
    write_json(manifest, receipt)
    return {**receipt, "cached": False}


def capture_kev(client: httpx.Client, root: Path) -> dict:
    with tempfile.TemporaryDirectory(dir=root) as staging:
        payload = Path(staging) / "catalog"
        meta = transfer(client, CISA, payload, 16 * 1024 * 1024)
        catalog = json.loads(payload.read_bytes())
        archive = Archive(
            "kev",
            "catalog",
            CISA,
            str(meta["sha256"]),
            utc_timestamp(catalog["dateReleased"]),
            int(meta["bytes"]),
            str(meta["sha256"]),
        )
        return capture(
            archive,
            root,
            client,
            supplied=payload,
            supplied_receipt=meta,
            expected=int(catalog["count"]),
        )


def key_paths(root: Path, receipts: Iterable[dict], source: str) -> list[str]:
    return [
        str(root / source / row["archive"]["key"] / row["archive"]["revision"] / "records.parquet")
        for row in receipts
        if row["archive"]["source"] == source
    ]


def previous_nvd(root: Path) -> list[dict]:
    path = root / "nvd-index.json"
    return json.loads(path.read_text()) if path.is_file() else []


def sync_years(root: Path, target: set[int], modified: Archive) -> set[int]:
    prior = previous_nvd(root)
    year_keys = {int(key) for row in prior if (key := row["archive"]["key"]).isdecimal()}
    deltas = [
        utc_timestamp(row["archive"]["published_at"])
        for row in prior
        if row["archive"]["key"] == "modified"
    ]
    # A seven-day threshold leaves a margin inside NVD's advertised eight-day window.
    if not deltas or (modified.published_at - max(deltas)).total_seconds() > 7 * 86400:
        return target
    if modified.published_at < max(deltas):
        raise DataError("NVD modified META predates the previously pinned cursor")
    return target - year_keys


def build_views(db: duckdb.DuckDBPyConnection, root: Path, receipts: list[dict]) -> None:
    for source in ("kev", "nvd", "cve"):
        selected = [row for row in receipts if row["archive"]["source"] == source]
        paths = key_paths(root, selected, source)
        if paths:
            db.register(
                f"{source}_artifact_order",
                pa.table(
                    {
                        "filename": paths,
                        "artifact_published_at": [
                            utc_timestamp(row["archive"]["published_at"]) for row in selected
                        ],
                    }
                ),
            )
            db.read_parquet(paths, filename=True).project(
                """cve_id, published_at, modified_at, status,
                   has_cvss, has_cwe, has_cpe, has_adp, has_ssvc, filename"""
            ).create_view(f"{source}_versions")
            db.sql(
                f"""SELECT v.* FROM {source}_versions v
                    JOIN {source}_artifact_order USING (filename)
                    QUALIFY row_number() OVER (
                        PARTITION BY cve_id
                        ORDER BY modified_at DESC NULLS LAST, artifact_published_at DESC,
                                 filename DESC
                    ) = 1"""
            ).create_view(source)


def kev_changes(db: duckdb.DuckDBPyConnection, root: Path) -> list[dict]:
    revisions = sorted(
        (
            json.loads(receipt.read_text())
            for receipt in (root / "kev/catalog").glob("*/receipt.json")
        ),
        key=lambda entry: (entry["archive"]["published_at"], entry["raw"]["retrieved_at"]),
    )
    changes = []
    for before, after in zip(revisions, revisions[1:]):
        left, right = key_paths(root, (before, after), "kev")
        db.read_parquet(left).create_view("kev_before", replace=True)
        db.read_parquet(right).create_view("kev_after", replace=True)
        rows = db.sql(
            """SELECT cve_id, CASE WHEN b.cve_id IS NULL THEN 'added'
                                   WHEN a.cve_id IS NULL THEN 'removed'
                                   ELSE 'modified' END AS action
                 FROM kev_before b FULL OUTER JOIN kev_after a USING (cve_id)
                WHERE b.payload IS DISTINCT FROM a.payload
                ORDER BY cve_id"""
        ).fetchall()
        changes.append(
            {
                "previous": before["archive"]["revision"],
                "current": after["archive"]["revision"],
                "changes": [{"cve_id": cve, "action": action} for cve, action in rows],
            }
        )
    return changes


def report(
    root: Path,
    captures: list[dict],
    receipts: list[dict],
    sources: set[str],
    years: list[int] | None,
    elapsed: float,
    errors: dict[str, str],
) -> None:
    summary: dict = {}
    with duckdb.connect(config={"memory_limit": "768MB", "threads": "2"}) as db:
        build_views(db, root, receipts)
        for source in sorted(sources):
            selected = [item for item in receipts if item["archive"]["source"] == source]
            if not selected:
                continue
            missing = {
                "kev": [],
                "nvd": ["cvss", "cwe", "cpe"],
                "cve": ["adp", "ssvc"],
            }[source]
            values = db.sql(
                "SELECT count(*)"
                + "".join(f", count_if(NOT has_{key})" for key in missing)
                + f" FROM {source}"
            ).fetchone()
            assert values is not None
            summary[source] = {
                "files": len(selected),
                "available_records_across_files": sum(
                    row["counts"]["available"] for row in selected
                ),
                "downloaded_records_across_files": sum(
                    row["counts"]["downloaded"] for row in selected
                ),
                "valid_records_across_files": sum(row["counts"]["valid"] for row in selected),
                "rejected_records": sum(row["counts"]["rejected"] for row in selected),
                "duplicates_within_files": sum(row["counts"]["duplicate"] for row in selected),
                "current_distinct_cves": values[0],
                "missing_enrichments": dict(zip(missing, values[1:], strict=True)),
                "cross_file_overlaps": sum(row["counts"]["valid"] for row in selected) - values[0],
                "archived_bytes": sum(row["raw"]["bytes"] for row in selected),
                "normalized_bytes": sum(row["normalized_bytes"] for row in selected),
            }
        matches = {}
        for left, right in (("nvd", "cve"), ("kev", "nvd"), ("kev", "cve")):
            if {left, right} <= summary.keys():
                result = db.sql(
                    f"SELECT count(*) FROM {left} JOIN {right} USING (cve_id)"
                ).fetchone()
                assert result is not None
                matches[f"{left}_{right}"] = {
                    "matched": result[0],
                    f"{left}_only": summary[left]["current_distinct_cves"] - result[0],
                    f"{right}_only": summary[right]["current_distinct_cves"] - result[0],
                }
        if {"nvd", "cve"} <= summary.keys():
            result = db.sql(
                """SELECT count_if(nvd.published_at IS NOT NULL AND cve.published_at IS NOT NULL
                                   AND nvd.published_at <> cve.published_at),
                          count_if((nvd.status = 'Rejected') IS DISTINCT FROM
                                   (cve.status = 'REJECTED'))
                     FROM nvd JOIN cve USING (cve_id)"""
            ).fetchone()
            assert result is not None
            summary["source_discrepancies"] = {
                "distinct_publication_timestamps_among_matched": result[0],
                "different_rejected_indicators_among_matched": result[1],
            }
        if "kev" in summary:
            changes = kev_changes(db, root)
            summary["kev"]["captured_revisions"] = len(changes) + 1
            write_json(root / "kev-changes.json", {"comparisons": changes})
    output = {
        "observed_at": datetime.now(UTC).isoformat(),
        "explicit_nvd_year_subset": years,
        "sources": summary,
        "cross_source_matches": matches,
        "source_errors": errors,
        "captures": [{**row, "cached": row.get("cached", True)} for row in captures],
        "elapsed_seconds": round(elapsed, 2),
    }
    write_json(root / ("report-" + "-".join(sorted(sources)) + ".json"), output)
    print(
        json.dumps(
            {"summary": summary, "cross_source_matches": matches, "source_errors": errors},
            sort_keys=True,
        )
    )


def assemble_nvd(root: Path, captures: list[dict], sync_nvd: bool) -> list[dict]:
    annual: dict[str, dict] = {}
    deltas: dict[str, dict] = {}
    for row in [*(previous_nvd(root) if sync_nvd else []), *captures]:
        entry = row["archive"]
        if entry["source"] != "nvd":
            continue
        if entry["key"] == "modified":
            deltas[entry["revision"]] = row
        else:
            annual[entry["key"]] = row
    return [*annual.values(), *deltas.values()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", nargs="+", choices=("kev", "nvd", "cve"))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--nvd-years", nargs="+", type=int)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--sync-nvd", action="store_true")
    args = parser.parse_args()
    env = project_environment()
    root = (args.root or Path(env.get("AEGIS_DATA_DIR") or "data") / "v2/vulnerabilities").resolve()
    root.mkdir(parents=True, exist_ok=True)
    with (root / ".lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.exit(1, "another V2 ingestion process is running\n")
        return run(root, set(args.sources), args.nvd_years, args.plan_only, args.sync_nvd)


def run(
    root: Path, sources: set[str], years: list[int] | None, plan_only: bool, sync_nvd: bool
) -> int:
    started = time.monotonic()
    receipts: list[dict] = []
    plan: list[Archive] = []
    errors: dict[str, str] = {}
    with httpx.Client(
        follow_redirects=True,
        timeout=20,
        headers={"User-Agent": "AEGIS AI public archive ingestion", "Accept-Encoding": "identity"},
    ) as client:
        if "nvd" in sources:
            try:
                modified = nvd_archive(client, root, "modified")
                target = set(
                    years
                    or range(2002, max(datetime.now(UTC).year, modified.published_at.year) + 1)
                )
                if any(y < 2002 or y > datetime.now(UTC).year + 1 for y in target):
                    raise DataError("NVD annual partition is outside the documented year range")
                if sync_nvd:
                    target = sync_years(root, target, modified)
                for year in sorted(target):
                    try:
                        plan.append(nvd_archive(client, root, str(year)))
                    except (DataError, KeyError, ValueError) as error:
                        errors[f"nvd/{year}/manifest"] = str(error)
                plan.append(modified)
            except (DataError, KeyError, ValueError) as error:
                errors["nvd/manifest"] = str(error)
        if "cve" in sources:
            try:
                plan.extend(cve_archives(client, root))
            except (DataError, KeyError, ValueError) as error:
                errors["cve/manifest"] = str(error)
        write_json(
            root / ("plan-" + "-".join(sorted(sources)) + ".json"),
            {
                "archives": [asdict(archive) for archive in plan],
                "compressed_bytes": sum(item.length or 0 for item in plan),
            },
        )
        if plan_only:
            if errors:
                print(json.dumps({"source_errors": errors}))
            return int(bool(errors))
        if "kev" in sources:
            try:
                receipts.append(capture_kev(client, root))
                emit(receipts[-1])
            except (DataError, KeyError, ValueError) as error:
                errors["kev/catalog"] = str(error)
        for archive in plan:
            try:
                receipts.append(capture(archive, root, client))
                emit(receipts[-1])
            except (BadZipFile, DataError, OSError, ValueError, ijson.JSONError) as error:
                identity = f"{archive.source}/{archive.key}"
                errors[identity] = str(error)
                print(json.dumps({"archive": identity, "error": str(error)}), flush=True)
    nvd = assemble_nvd(root, receipts, sync_nvd)
    selected = [row for row in receipts if row["archive"]["source"] != "nvd"] + nvd
    report(root, receipts, selected, sources, years, time.monotonic() - started, errors)
    issues = any(row["counts"]["rejected"] or row["counts"]["duplicate"] for row in selected)
    if (
        "nvd" in sources
        and years is None
        and not issues
        and not any(key.startswith("nvd/") for key in errors)
    ):
        write_json(root / "nvd-index.json", nvd)
    return int(issues or bool(errors))


def emit(receipt: dict) -> None:
    archive = receipt["archive"]
    print(
        json.dumps(
            {
                "source": archive["source"],
                "key": archive["key"],
                "cached": receipt["cached"],
                **receipt["counts"],
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BadZipFile, DataError, KeyError, ValueError, OSError, ijson.JSONError) as error:
        raise SystemExit(f"V2 source capture failed: {error}") from None
