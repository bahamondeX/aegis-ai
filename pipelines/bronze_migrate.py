"""Inventory verified V2 data and migrate an explicitly approved selection."""

import argparse
import json
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError

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
from pipelines.bulk_epss import git_blob_sha1
from pipelines.config import project_environment
from pipelines.epss_bronze import archive_members, commit_date
from pipelines.io import DataError, digest
from pipelines.kev_history import CATALOG, run_git

SOURCES = ("kev", "kev-history", "nvd", "cve-program", "epss", "network")


@dataclass(frozen=True)
class Item:
    name: str
    ref: ObjectRef
    path: Path
    git_revision: str | None = None

    @contextmanager
    def materialize(self) -> Iterator[Path]:
        if self.git_revision is None:
            yield self.path
            return
        with tempfile.TemporaryDirectory() as scratch:
            file = Path(scratch) / "catalog"
            file.write_bytes(
                run_git(["--git-dir", str(self.path), "show", f"{self.git_revision}:{CATALOG}"])
            )
            yield file


def checked(
    root: Path,
    path: Path,
    source: str,
    kind: str,
    expected: str | None = None,
    size: int | None = None,
) -> Item:
    if not path.is_file() or not path.resolve().is_relative_to(root):
        raise DataError("planned artifact is missing or escapes the verified inventory")
    ref = artifact(source, kind, path)
    if (expected is not None and ref.sha256 != expected) or (size is not None and ref.size != size):
        raise DataError(f"checksum or size mismatch in {path.relative_to(root)}")
    return Item(path.relative_to(root).as_posix(), ref, path)


def good_rows(receipt: dict) -> None:
    counts = receipt["counts"]
    if (
        counts["rejected"]
        or counts["duplicate"]
        or counts["available"] != counts["downloaded"]
        or counts["available"] != counts["valid"]
    ):
        raise DataError("source receipt does not reconcile its verified record count")


def captures(root: Path, source: str) -> Iterator[Item]:
    catalog = "cve" if source == "cve-program" else source
    folder = root / ("epss" if source == "epss" else f"vulnerabilities/{catalog}")
    for path in sorted(folder.rglob("receipt.json")):
        receipt = json.loads(path.read_text())
        good_rows(receipt)
        yield checked(root, path, source, "receipts")
        yield checked(
            root,
            path.parent / "payload",
            source,
            "raw",
            receipt["raw"]["sha256"],
            receipt["raw"]["bytes"],
        )
        yield checked(
            root,
            path.parent / "records.parquet",
            source,
            "normalized",
            receipt["normalized_sha256"],
            receipt["normalized_bytes"],
        )
    if source == "epss":
        for path in sorted((folder / "archive-manifests").glob("*.json")):
            yield checked(root, path, source, "manifests")


def historical_kev(root: Path) -> Iterator[Item]:
    folder = root / "kev-history"
    manifest = folder / "history.json"
    if not manifest.exists():
        return
    yield checked(root, manifest, "kev-history", "manifests")
    repo = folder / "source.git"
    if not repo.resolve().is_relative_to(root):
        raise DataError("KEV repository escapes the local inventory")
    for segment in json.loads(manifest.read_text())["segments"]:
        yield checked(
            root,
            folder / "segments" / segment["head"] / "changes.parquet",
            "kev-history",
            "normalized",
            segment["normalized_sha256"],
            segment["normalized_bytes"],
        )
        for item in segment["catalog_revisions"]:
            revision = item["source_revision"]
            checksum = item["raw_sha256"]
            if not re.fullmatch(r"[a-f0-9]{40}", revision):
                raise DataError("invalid KEV history revision")
            if item["state"] != "valid":
                continue
            raw = run_git(["--git-dir", str(repo), "show", f"{revision}:{CATALOG}"])
            if digest(raw) != checksum:
                raise DataError("KEV history revision differs from its archived receipt")
            yield Item(
                f"kev-history/commits/{revision}",
                ObjectRef(f"{PREFIX}/kev-history/raw/{checksum}", len(raw), checksum),
                repo,
                revision,
            )


def network(root: Path) -> Iterator[Item]:
    for family in ("wdi", "rir"):
        for path in sorted((root / family).rglob("receipt.json")):
            receipt = json.loads(path.read_text())
            yield checked(root, path, "network", "receipts")
            if family == "rir":
                yield checked(
                    root,
                    path.parent / "registration-context.parquet",
                    "network",
                    "normalized",
                    receipt["normalized_sha256"],
                    receipt["normalized_bytes"],
                )
            else:
                for name, metadata in receipt["captures"].items():
                    yield checked(
                        root,
                        path.parent / f"{name}.json",
                        "network",
                        "raw",
                        metadata["sha256"],
                        metadata["bytes"],
                    )
                for name, metadata in receipt["files"].items():
                    yield checked(
                        root,
                        path.parent / f"{name}.parquet",
                        "network",
                        "normalized",
                        metadata["sha256"],
                        metadata["bytes"],
                    )


def inventory(root: Path, sources: list[str]) -> list[Item]:
    items = []
    for source in sorted(set(sources)):
        if source == "kev-history":
            selected = list(historical_kev(root))
        elif source == "network":
            selected = list(network(root))
        else:
            selected = list(captures(root, source))
        if not selected:
            raise DataError(f"no verified artifacts found for {source}")
        items.extend(selected)
    return items


def describe(items: list[Item]) -> dict:
    catalog = [{"name": item.name, "object": asdict(item.ref)} for item in items]
    unique = {item.ref.key: item.ref for item in items}
    totals: dict[str, dict[str, int]] = {}
    for key, ref in unique.items():
        source = key.split("/")[2]
        total = totals.setdefault(source, {"objects": 0, "bytes": 0})
        total["objects"] += 1
        total["bytes"] += ref.size
    return {
        "id": digest(json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode()),
        "objects": len(unique),
        "bytes": sum(ref.size for ref in unique.values()),
        "sources": totals,
        "inventory": catalog,
    }


def migrate_epss_dates(store: BronzeStore, items: list[Item], refs: dict) -> int:
    listed: dict[tuple[str, str], str] = {}
    by_name = {item.name: item for item in items}
    for item in items:
        if item.name.startswith("epss/archive-manifests/"):
            tree = json.loads(item.path.read_bytes())
            for day, member in archive_members(tree).items():
                listed[day, member["sha"]] = tree["sha"]
    committed = 0
    for item in items:
        if not item.name.startswith("epss/score_date=") or not item.name.endswith("/receipt.json"):
            continue
        receipt = json.loads(item.path.read_bytes())
        raw = by_name[item.name.removesuffix("receipt.json") + "payload"]
        parquet = by_name[item.name.removesuffix("receipt.json") + "records.parquet"]
        day, blob = receipt["score_date"], git_blob_sha1(raw.path)
        if (day, blob) not in listed:
            continue
        commit_date(
            store,
            {
                **receipt,
                "upstream_git_blob_sha1": blob,
                "source_tree": listed[day, blob],
                "raw_object": refs[raw.ref.key],
                "normalized_object": refs[parquet.ref.key],
            },
        )
        committed += 1
    return committed


def migrate(store: BronzeStore, items: list[Item], plan: dict, attempt: int) -> dict:
    if type(attempt) is not int or not 1 <= attempt <= 3:
        raise DataError("migration attempt is outside its durable budget")
    prefix = f"{PREFIX}/manifests/migrations/{plan['id']}"
    final_key = prefix + "/committed.json"
    if committed := record(store, final_key):
        for entry in committed["objects"]:
            observed = store.inspect(entry["key"])
            if observed != ObjectRef(**entry):
                raise DataError("previously committed migration object failed verification")
        return {**committed, "reused_manifest": True}
    claim = f"{prefix}/attempts/{attempt}.json"
    if not put_record(
        store, claim, {"bytes": plan["bytes"], "objects": plan["objects"]}, exact=False
    ):
        raise DataError("migration attempt already reserved; inspect it before approving a retry")
    refs = {}
    uploaded = 0
    for item in items:
        if item.ref.key in refs:
            continue
        observed = store.inspect(item.ref.key)
        if observed is None:
            with item.materialize() as path:
                observed, wrote = ensure(store, item.ref, path)
                uploaded += wrote
        if not item.ref.matches(observed):
            raise DataError("remote migration artifact differs from its inventory")
        refs[item.ref.key] = asdict(observed)
    manifest = {
        "inventory_id": plan["id"],
        "objects": list(refs.values()),
        "inventory": [{"name": i.name, "key": i.ref.key} for i in items],
        "epss_dates_committed": migrate_epss_dates(store, items, refs),
    }
    put_record(store, final_key, manifest)
    return {**manifest, "uploaded": uploaded, "reused_manifest": False}


def authorized_store(env: dict[str, str], plan: dict) -> S3Bronze:
    settings = Settings.load(environment=env)
    scope = f"{settings.account}/{settings.region}/{settings.project}/bronze-migration/{plan['id']}"
    try:
        ceiling = Decimal(env.get("AEGIS_V2_MIGRATION_USD", ""))
        byte_limit = int(env.get("AEGIS_V2_MIGRATION_BYTES", "0"))
        object_limit = int(env.get("AEGIS_V2_MIGRATION_OBJECTS", "0"))
    except (InvalidOperation, ValueError):
        raise DataError("set the approved V2 migration spending and transfer limits") from None
    if (
        env.get("AEGIS_V2_MIGRATION_APPROVAL") != scope
        or not ceiling.is_finite()
        or ceiling <= 0
        or plan["bytes"] > byte_limit
        or plan["objects"] > object_limit
    ):
        raise DataError("separate V2 migration approval for this inventory is required")
    required = Decimal("0.25") + Decimal(plan["objects"]) * Decimal("0.00012")
    required += Decimal(plan["bytes"]) * Decimal("0.023") / Decimal(10**9)
    if ceiling < required:
        raise DataError("approved V2 migration ceiling does not cover the bounded request estimate")
    return verified_lake(settings)


def verified_lake(settings: Settings) -> S3Bronze:
    session, _ = settings.identity()
    from infra.operations import stack_outputs

    outputs = stack_outputs(session, settings)
    bucket, key = outputs["LakeBucket"], outputs["KmsKey"]
    if not key.startswith(f"arn:aws:kms:{settings.region}:{settings.account}:key/"):
        raise DataError("existing lake KMS key is outside the approved scope")
    s3 = session.client("s3", config=SDK_CONFIG)
    owned = {"Bucket": bucket, "ExpectedBucketOwner": settings.account}
    s3.head_bucket(**owned)
    if s3.get_bucket_versioning(**owned).get("Status") != "Enabled":
        raise DataError("V2 requires the existing versioned lake bucket")
    return S3Bronze(s3, bucket, settings.account, key)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--source", choices=SOURCES, action="append")
    parser.add_argument("--local-store", type=Path)
    parser.add_argument("--apply", metavar="INVENTORY_ID")
    parser.add_argument("--attempt", choices=(1, 2, 3), default=1, type=int)
    args = parser.parse_args()
    env = project_environment()
    root = (args.root or Path(env.get("AEGIS_DATA_DIR") or "data") / "v2").resolve()
    items = inventory(root, args.source or list(SOURCES))
    plan = describe(items)
    if args.apply:
        if args.apply != plan["id"]:
            raise DataError("selected inventory differs from its reviewed identifier")
        store: BronzeStore = (
            LocalBronze(args.local_store) if args.local_store else authorized_store(env, plan)
        )
        result = migrate(store, items, plan, args.attempt)
        print(
            json.dumps(
                {
                    "inventory_id": plan["id"],
                    "objects": len(result["objects"]),
                    "uploaded": result.get("uploaded", 0),
                    "reused_manifest": result["reused_manifest"],
                }
            )
        )
    else:
        print(json.dumps(plan, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except ClientError as error:
        raise SystemExit(f"V2 migration AWS error: {error.response['Error']['Code']}") from None
    except (DataError, OSError, ValueError, KeyError, BotoCoreError) as error:
        raise SystemExit(f"V2 migration failed: {error}") from None
