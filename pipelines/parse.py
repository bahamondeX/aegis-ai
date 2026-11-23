import gzip
import io
import re
from datetime import UTC, datetime

import polars as pl

from pipelines.io import DataError
from schemas.sources import KevCatalog, NvdRecord, NvdResponse


def parse_kev(data: bytes) -> KevCatalog:
    catalog = KevCatalog.model_validate_json(data)
    ids = {entry.cveID for entry in catalog.vulnerabilities}
    if len(ids) != catalog.count or len(ids) != len(catalog.vulnerabilities):
        raise DataError("cisa: catalog count or CVE uniqueness mismatch")
    return catalog


def parse_epss(data: bytes) -> tuple[datetime, str, pl.DataFrame]:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        header = stream.readline(512).decode("ascii").rstrip()
        match = re.fullmatch(r"#model_version:([^,]+),score_date:([^,]+)(?:,.*)?", header)
        if not match:
            raise DataError("epss: missing model version or score date")
        published = datetime.fromisoformat(match[2])
        if published.tzinfo is None and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", match[2]):
            raise DataError("epss: timestamp is missing a UTC offset")
        published = (
            published.replace(tzinfo=UTC)
            if published.tzinfo is None
            else (published.astimezone(UTC))
        )
        payload = stream.read(64 * 1024 * 1024 + 1)
        if len(payload) > 64 * 1024 * 1024:
            raise DataError("epss: decompressed payload exceeds limit")
    rows = pl.read_csv(
        io.BytesIO(payload),
        schema_overrides={"cve": pl.String, "epss": pl.Float64, "percentile": pl.Float64},
    )
    if rows.columns != ["cve", "epss", "percentile"] or rows.is_empty():
        raise DataError("epss: unexpected or empty score table")
    rows = rows.with_columns(pl.col("cve").str.strip_chars().str.to_uppercase())
    valid = (
        pl.col("cve").str.contains(r"^CVE-[0-9]{4}-[0-9]{4,}$")
        & pl.col("epss").is_between(0, 1)
        & pl.col("percentile").is_between(0, 1)
    )
    if not rows.select(valid.fill_null(False).all()).item():
        raise DataError("epss: invalid CVE, probability or percentile")
    if rows["cve"].n_unique() != rows.height:
        raise DataError("epss: duplicate CVE for score date")
    return published, match[1], rows


def parse_nvd(data: bytes, requested: list[str]) -> tuple[NvdResponse, dict[str, NvdRecord]]:
    response = NvdResponse.model_validate_json(data)
    records = {entry.cve.id: entry.cve for entry in response.vulnerabilities}
    if (
        response.startIndex != 0
        or response.totalResults != len(records)
        or len(records) != len(response.vulnerabilities)
        or not set(records).issubset(requested)
        or response.resultsPerPage < len(records)
    ):
        raise DataError("nvd: incomplete page, duplicate CVE or out-of-cohort result")
    return response, records
