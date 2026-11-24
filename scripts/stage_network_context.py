"""Stage the vetted CRTC Open Data projection for one existing local threat release."""

import argparse
from datetime import date, datetime
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID
from zipfile import ZipFile

import polars as pl
from pydantic import HttpUrl

from backend.geography import CRTC_PUBLICATION, CRTC_SHA, ContextRelease, NetworkContext
from pipelines.io import DataError, digest, selected_snapshot
from pipelines.normalize import identity


def stage(root: Path, snapshot: UUID, archive: Path, retrieved: datetime) -> Path:
    selected_snapshot(root, snapshot)
    with archive.open("rb") as file:
        raw = file.read(40_000_001)
    if len(raw) > 40_000_000 or digest(raw) != CRTC_SHA or retrieved.utcoffset() is None:
        raise DataError("network archive or capture time is invalid")
    with ZipFile(BytesIO(raw)) as table:
        data = table.read("C-T5.csv")
    rows = pl.read_csv(BytesIO(data), skip_rows=4, has_header=False)
    latest = rows.filter(pl.col("column_1").eq("1 or more")).select("column_2", "column_6")
    if latest.height != 14 or latest.get_column("column_2").n_unique() != latest.height:
        raise DataError("CRTC projection grain changed")
    records = tuple(
        NetworkContext(
            record_id=identity(CRTC_SHA, "C-T5", "1 or more", area, "2021"),
            kind="published_coverage",
            country_iso2="CA",
            region=area if area != "Canada" else None,
            scope="Population covered by at least one facilities-based LTE wireless network",
            source_date=date(2026, 8, 20),
            reporting_year=2021,
            population_coverage=float(percent.removesuffix("%")) / 100,
            retrieved_at=retrieved,
            publication=HttpUrl(CRTC_PUBLICATION),
            publisher="Canadian Radio-television and Telecommunications Commission",
            license="Open Government Licence – Canada",
            checksum=CRTC_SHA,
        )
        for area, percent in latest.iter_rows()
    )
    payload = ContextRelease(snapshot_id=snapshot, records=records).model_dump_json().encode()
    parent = root / "network"
    parent.mkdir(exist_ok=True)
    location = parent / str(snapshot)
    with TemporaryDirectory(dir=parent) as temporary:
        entry = Path(temporary) / "release"
        entry.mkdir()
        (entry / "network-context.json").write_bytes(payload)
        (entry / "manifest.json").write_text(digest(payload))
        try:
            entry.rename(location)
        except OSError:
            if not location.is_dir() or (location / "network-context.json").read_bytes() != payload:
                raise DataError(
                    "an immutable network projection already covers this release"
                ) from None
    return location


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("data"))
    parser.add_argument("--snapshot", type=UUID, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--retrieved", type=datetime.fromisoformat, required=True)
    args = parser.parse_args()
    print(stage(args.root, args.snapshot, args.archive, args.retrieved))


if __name__ == "__main__":
    main()
