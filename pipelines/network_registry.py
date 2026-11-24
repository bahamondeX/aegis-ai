"""Measure coarse RIR ASN registration context from the NRO daily report."""

import argparse
import hashlib
import json
import re
import time
from collections import Counter
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from itertools import chain
from pathlib import Path

import httpx
import pyarrow as pa
import pyarrow.parquet as pq

from pipelines.config import project_environment
from pipelines.fetch import MAX_ATTEMPTS, retry_after
from pipelines.io import DataError, file_digest, write_json

URI = "https://ftp.ripe.net/pub/stats/ripencc/nro-stats/latest/nro-delegated-stats"
REGISTERED = {"allocated", "assigned", "legacy"}
REGISTRIES = {"afrinic", "apnic", "arin", "lacnic", "ripencc"}
NON_COUNTRY_CODES = {"AP", "EU", "ZZ"}
BLOCK = 4 * 1024 * 1024


def analyze(blocks: Iterable[bytes]) -> tuple[dict, list[dict]]:
    checksum = hashlib.sha256()
    row_totals: Counter[tuple[str, str, str | None]] = Counter()
    number_totals: Counter[tuple[str, str, str | None]] = Counter()
    statuses: Counter[str] = Counter()
    pending = b""
    size = lines = asn_rows = 0
    version = declared_lines = declared_asn_rows = None
    started = time.monotonic()
    for block in chain(blocks, (None,)):
        if block is None:
            records = [pending]
            pending = b""
        else:
            size += len(block)
            if size > 128 * 1024 * 1024 or time.monotonic() - started > 180:
                raise DataError("NRO registry report exceeded the transfer bound")
            checksum.update(block)
            records = (pending + block).split(b"\n")
            pending = records.pop()
            if len(pending) > 4096:
                raise DataError("NRO registry report contains an oversized row")
        for record in records:
            if not record or record.startswith(b"#"):
                continue
            fields = record.decode("ascii").rstrip("\r").split("|")
            if fields[0] == "2":
                if fields[1] != "nro" or version:
                    raise DataError("unexpected NRO delegated report header")
                version = datetime.strptime(fields[2], "%Y%m%d").date().isoformat()
                declared_lines = int(fields[3])
                continue
            if fields[-1] == "summary":
                if fields[2] == "asn":
                    declared_asn_rows = int(fields[4])
                continue
            lines += 1
            if fields[2] != "asn":
                continue
            registry, country, _, start, count, _, status = fields[:7]
            asn_rows += 1
            statuses[status] += 1
            if status not in REGISTERED:
                continue
            first, numbers = int(start), int(count)
            if registry not in REGISTRIES or first < 1 or numbers < 1 or first + numbers > 2**32:
                raise DataError("invalid ASN registration row")
            if country and not re.fullmatch(r"[A-Z]{2}", country):
                raise DataError("invalid RIR registration country code")
            code = country if country and country not in NON_COUNTRY_CODES else None
            row_totals[registry, status, code] += 1
            number_totals[registry, status, code] += numbers
    if not version or asn_rows != declared_asn_rows or lines != declared_lines:
        raise DataError(
            f"NRO row totals differ from metadata: records {lines}/{declared_lines}, "
            f"ASN rows {asn_rows}/{declared_asn_rows}"
        )
    rows = [
        {
            "report_date": version,
            "registry": key[0],
            "registration_status": key[1],
            "registration_country_code": key[2],
            "reported_registration_rows": row_totals[key],
            "as_numbers_in_reported_ranges": numbers,
        }
        for key, numbers in sorted(number_totals.items(), key=lambda item: str(item[0]))
    ]
    country_codes = {row["registration_country_code"] for row in rows}
    country_codes.discard(None)
    return {
        "schema_version": 1,
        "source": URI,
        "source_date": version,
        "retrieved_at": datetime.now(UTC).isoformat(),
        "source_sha256": checksum.hexdigest(),
        "source_bytes": size,
        "source_records_available": declared_lines,
        "source_records_downloaded": lines,
        "asn_rows_available": declared_asn_rows,
        "asn_rows_downloaded": asn_rows,
        "source_statuses": dict(statuses),
        "registered_rows": sum(row_totals.values()),
        "source_registration_country_codes": len(country_codes),
        "registries": sorted({row["registry"] for row in rows}),
        "aggregate_rows": len(rows),
        "geographic_basis": "rir_registration",
        "publication": "local_source_qualification",
    }, rows


def source_blocks(client: httpx.Client) -> Iterator[bytes]:
    started = time.monotonic()
    response = client.head(URI, headers={"Range": "bytes=0-0"})
    length = re.fullmatch(r"bytes 0-0/(\d+)", response.headers.get("Content-Range", ""))
    etag = response.headers.get("ETag")
    if response.status_code != 206 or not length or not etag:
        raise DataError("NRO report did not advertise a stable byte range")
    size = int(length[1])
    if not 0 < size <= 128 * 1024 * 1024:
        raise DataError("NRO report exceeds its transfer size bound")
    for offset in range(0, size, BLOCK):
        end = min(offset + BLOCK, size) - 1
        expected = f"bytes {offset}-{end}/{size}"
        for attempt in range(MAX_ATTEMPTS):
            delay = 0.0
            try:
                with client.stream(
                    "GET", URI, headers={"Range": f"bytes={offset}-{end}", "If-Range": etag}
                ) as body:
                    if (
                        body.status_code == 206
                        and body.headers.get("Content-Range") == expected
                        and body.headers.get("ETag") == etag
                    ):
                        contents = bytearray()
                        for chunk in body.iter_bytes():
                            if time.monotonic() - started > 180:
                                raise DataError("NRO byte ranges exceeded the transfer time bound")
                            contents.extend(chunk)
                            if len(contents) > end - offset + 1:
                                raise DataError("NRO response returned an oversized byte range")
                        if len(contents) == end - offset + 1:
                            yield bytes(contents)
                            break
                    elif body.status_code == 429 or 500 <= body.status_code <= 599:
                        delay = retry_after(body.headers.get("Retry-After"))
                    else:
                        raise DataError(f"NRO byte range returned HTTP {body.status_code}")
            except httpx.TransportError:
                if attempt + 1 == MAX_ATTEMPTS:
                    raise
            if delay > 20:
                raise DataError("NRO requested retry beyond the transfer time bound")
            time.sleep(max(delay, 2**attempt))
        else:
            raise DataError("NRO byte range remained unavailable")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()
    environment = project_environment()
    root = args.root or Path(environment.get("AEGIS_DATA_DIR") or "data") / "v2/rir"
    with httpx.Client(
        follow_redirects=True, timeout=20, headers={"Accept-Encoding": "identity"}
    ) as client:
        checksum = client.get(URI + ".sha256")
        candidates = checksum.text.split() if checksum.status_code == 200 else []
        if not candidates or not re.fullmatch(r"[a-f0-9]{64}", candidates[0]):
            raise DataError("NRO report checksum is unavailable")
        receipt, rows = analyze(source_blocks(client))
        if receipt["source_sha256"] != candidates[0]:
            raise DataError("NRO content differs from the official checksum")
    if not rows:
        raise DataError("NRO reported no ASN registrations")
    snapshot = root / receipt["source_date"] / receipt["source_sha256"]
    snapshot.mkdir(parents=True, exist_ok=True)
    file = snapshot / "registration-context.parquet"
    partial = file.with_suffix(".part")
    pq.write_table(pa.Table.from_pylist(rows), partial, compression="zstd")
    partial.replace(file)
    write_json(
        snapshot / "receipt.json",
        {
            **receipt,
            "normalized_bytes": file.stat().st_size,
            "normalized_sha256": file_digest(file),
        },
    )
    print(json.dumps({"artifact": str(snapshot), **receipt}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (DataError, ValueError, IndexError, httpx.TransportError) as error:
        raise SystemExit(f"RIR context qualification failed: {error}") from None
