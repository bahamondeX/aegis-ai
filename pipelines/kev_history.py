"""Archive CISA's official KEV repository history as a local change log."""

import argparse
import fcntl
import json
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
from pydantic import ValidationError

from pipelines.bulk_archive import check_space
from pipelines.config import project_environment
from pipelines.io import DataError, digest, file_digest, write_json
from pipelines.parse import parse_kev

ORIGIN = "https://github.com/cisagov/kev-data.git"
REF = "refs/heads/develop"
CATALOG = "known_exploited_vulnerabilities.json"
SCHEMA = pa.schema(
    [
        ("cve_id", pa.string()),
        ("action", pa.string()),
        ("catalog_released_at", pa.timestamp("us", tz="UTC")),
        ("source_revision", pa.string()),
        ("payload", pa.large_string()),
    ]
)


def run_git(command: list[str]) -> bytes:
    result = subprocess.run(
        ["git", *command],
        capture_output=True,
        check=False,
        timeout=120,
    )
    if result.returncode:
        raise DataError(f"official CISA repository git {command[0]} exited {result.returncode}")
    return result.stdout


def catalog(raw: bytes) -> tuple[dict, dict[str, dict]]:
    parsed = parse_kev(raw)
    mapping = {row["cveID"]: row for row in json.loads(raw)["vulnerabilities"]}
    return {
        "available": parsed.count,
        "valid": len(mapping),
        "source_date": parsed.dateReleased,
        "source_version": parsed.catalogVersion,
        "raw_sha256": digest(raw),
    }, mapping


def change_rows(before: dict, current: dict, ref: str, released: datetime) -> list[dict]:
    rows = []
    for cve_id in sorted(set(before) | set(current)):
        if before.get(cve_id) == current.get(cve_id):
            continue
        payload = current.get(cve_id)
        action = "removed" if payload is None else "added" if cve_id not in before else "modified"
        rows.append(
            {
                "cve_id": cve_id,
                "action": action,
                "catalog_released_at": released,
                "source_revision": ref,
                "payload": json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
                if payload is not None
                else None,
            }
        )
    return rows


def synchronize(root: Path) -> dict:
    repo = root / "source.git"
    if not repo.exists():
        check_space(root)
        temporary = root / "source.git.staging"
        run_git(
            [
                "clone",
                "--bare",
                "--single-branch",
                "--branch",
                "develop",
                "--no-tags",
                ORIGIN,
                str(temporary),
            ]
        )
        temporary.replace(repo)
    else:
        # An explicit refspec permits only fast-forward and leaves historical objects reachable.
        run_git(["--git-dir", str(repo), "fetch", "--no-tags", ORIGIN, f"{REF}:{REF}"])
    command = ["--git-dir", str(repo)]
    head = run_git([*command, "rev-parse", REF]).decode().strip()
    manifest = root / "history.json"
    prior = json.loads(manifest.read_text()) if manifest.is_file() else None
    if prior is not None:
        for segment in prior["segments"]:
            path = root / "segments" / segment["head"] / "changes.parquet"
            if file_digest(path) != segment["normalized_sha256"]:
                raise DataError("KEV history segment failed its recorded checksum")
        if head == prior["head"]:
            return prior
        run_git([*command, "merge-base", "--is-ancestor", prior["head"], head])
    last_valid = prior["last_valid_revision"] if prior else None
    gap = list(prior["unresolved_malformed_revisions"]) if prior else []
    if last_valid is not None:
        _, before = catalog(run_git([*command, "show", f"{last_valid}:{CATALOG}"]))
    else:
        before = {}
    revision_range = f"{prior['head']}..{head}" if prior else head
    refs = (
        run_git(
            [
                *command,
                "log",
                "--reverse",
                "--first-parent",
                "--format=%H",
                revision_range,
                "--",
                CATALOG,
            ]
        )
        .decode()
        .splitlines()
    )
    folder = root / "segments" / head
    folder.mkdir(parents=True, exist_ok=True)
    final, staging = folder / "changes.parquet", folder / "changes.part"
    revisions = []
    totals: Counter[str] = Counter()
    try:
        with pq.ParquetWriter(staging, SCHEMA, compression="zstd") as writer:
            for ref in refs:
                raw = run_git([*command, "show", f"{ref}:{CATALOG}"])
                try:
                    meta, current = catalog(raw)
                except (DataError, ValidationError) as error:
                    reason = (
                        error.errors(include_input=False)[0]["type"]
                        if isinstance(error, ValidationError)
                        else "catalog_count_or_uniqueness"
                    )
                    revisions.append(
                        {
                            "source_revision": ref,
                            "raw_sha256": digest(raw),
                            "state": "malformed",
                            "reason": reason,
                        }
                    )
                    gap.append(ref)
                    continue
                changes = change_rows(before, current, ref, meta["source_date"])
                actions = Counter(row["action"] for row in changes)
                if changes:
                    writer.write_table(pa.Table.from_pylist(changes, schema=SCHEMA))
                totals.update(actions)
                revisions.append(
                    {
                        "source_revision": ref,
                        **meta,
                        "state": "valid",
                        "changes": dict(actions),
                        "preceding_malformed_revisions": gap,
                    }
                )
                before = current
                last_valid = ref
                gap = []
        staging.replace(final)
    finally:
        staging.unlink(missing_ok=True)
    segment = {
        "head": head,
        "last_valid_revision": last_valid,
        "unresolved_malformed_revisions": gap,
        "normalized_bytes": final.stat().st_size,
        "normalized_sha256": file_digest(final),
        "change_counts": dict(totals),
        "catalog_revisions": revisions,
    }
    result = {
        "schema_version": 1,
        "source": ORIGIN,
        "ref": REF,
        "head": head,
        "observed_at": datetime.now(UTC),
        "license": "CC0-1.0",
        "segments": [*(prior["segments"] if prior else []), segment],
    }
    write_json(manifest, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()
    env = project_environment()
    root = (args.root or Path(env.get("AEGIS_DATA_DIR") or "data") / "v2/kev-history").resolve()
    root.mkdir(parents=True, exist_ok=True)
    with (root / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = synchronize(root)
    totals: Counter[str] = Counter()
    for segment in result["segments"]:
        totals.update(segment["change_counts"])
    revisions = [row for segment in result["segments"] for row in segment["catalog_revisions"]]
    print(
        json.dumps(
            {
                "source": result["source"],
                "head": result["head"],
                "artifact": str(root / "history.json"),
                "revisions": len(revisions),
                "valid_revisions": sum(row["state"] == "valid" for row in revisions),
                "malformed_revisions": sum(row["state"] == "malformed" for row in revisions),
                "changes": dict(totals),
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (DataError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"KEV history capture failed: {error}") from None
