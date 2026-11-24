import argparse
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from pipelines.config import configured_snapshot, project_environment
from pipelines.io import DataError, selected_snapshot
from pipelines.publish import ingest, validate_published, verify_replay
from pipelines.query import Query, connect, query


def report(event: str, **fields: Any) -> None:
    print(
        json.dumps(
            {"event": event, "timestamp": datetime.now(UTC), **fields}, sort_keys=True, default=str
        ),
        flush=True,
    )


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AEGIS local data pipeline")
    parser.add_argument("--data-dir", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("ingest")
    capture.add_argument("--env-file", type=Path, default=Path(".env"))
    capture.add_argument("--nvd-limit", default=20, type=int, choices=range(1, 21))
    for command in ("validate", "query", "verify", "test"):
        commands.add_parser(command).add_argument("--snapshot", type=UUID)
    return parser.parse_args()


def run_tests(root: Path, folder: Path) -> int:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        env={**os.environ, "AEGIS_DATA_DIR": str(root), "AEGIS_SNAPSHOT": folder.name},
        check=False,
    ).returncode


def main() -> int:
    args = arguments()
    try:
        environment = project_environment()
        root = (args.data_dir or Path(environment.get("AEGIS_DATA_DIR") or "data")).resolve()
        if args.command == "ingest":
            folder, manifest = ingest(root, args.env_file, args.nvd_limit)
            report("ingest", artifact=folder / "manifest.json", **manifest)
            return 0 if manifest["status"] == "ok" else 2

        folder = selected_snapshot(root, args.snapshot or configured_snapshot(environment))
        if args.command == "test":
            return run_tests(root, folder)

        manifest = validate_published(root, folder)
        if args.command == "query":
            with connect(folder / "aegis.duckdb") as db:
                top = query(db, Query.RANKING, limit=5)
                report(
                    "query",
                    snapshot=folder.name,
                    coverage=query(db, Query.COVERAGE),
                    join_coverage=manifest["join_coverage"],
                    ranking_sample={"top_rows": len(top), "top_epss": [row["epss"] for row in top]},
                    relationship_edges=(
                        manifest["row_counts"]["bridge_cve_product"]
                        + manifest["row_counts"]["bridge_cve_cwe"]
                    ),
                    geography=manifest["geometry"],
                    geographic_rows=len(query(db, Query.GEO)),
                )
        elif args.command == "verify":
            test_code = run_tests(root, folder)
            if test_code:
                return test_code
            verify_replay(root, folder, manifest)
            report(
                "verified",
                snapshot=folder.name,
                replay="identical Parquet SHA-256 and sampled query results",
                status=manifest["status"],
                **manifest["join_coverage"],
            )
        else:
            report("validated", artifact=folder / "manifest.json", **manifest)
        return 0 if manifest["status"] == "ok" else 2
    except (DataError, FileNotFoundError) as error:
        report("error", error=str(error))
        return 1


if __name__ == "__main__":
    sys.exit(main())
