"""Small synthetic fixtures for archive, reconciliation and date-boundary contracts."""

import gzip
import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from zipfile import ZipFile

import duckdb
import httpx
import pyarrow.parquet as pq
import pytest

from pipelines import bulk_epss
from pipelines import bulk_vulnerabilities as bulk
from pipelines.bulk_archive import Archive, transfer, verify_archive
from pipelines.io import DataError, digest, write_json

PUBLISHED = datetime(2026, 1, 1, tzinfo=UTC)


def test_nvd_archives_verify_the_decompressed_digest_and_keep_source_values(tmp_path):
    source = {
        "cve": {
            "id": "CVE-2000-0012",
            "published": "2001-01-01T00:00:00",
            "vulnStatus": "Analyzed",
            "metrics": {"cvssMetricV2": [{"source": "a", "cvssData": {"baseScore": 5.1}}]},
            "configurations": [{"operator": "AND", "nodes": [{"negate": True}]}],
            "references": [{"url": "https://vendor.example/advisory"}],
        }
    }
    wrapper = json.dumps({"vulnerabilities": [source, source, {"cve": {"id": "bad"}}]}).encode()
    raw = tmp_path / "feed.gz"
    raw.write_bytes(gzip.compress(wrapper))
    archive = Archive(
        "nvd",
        "2002",
        "https://example.test/feed.gz",
        digest(wrapper),
        PUBLISHED,
        uncompressed_length=len(wrapper),
        uncompressed_sha256=digest(wrapper),
    )
    verify_archive(archive, raw, digest(raw.read_bytes()))
    out = tmp_path / "records.parquet"
    result = bulk.normalize(archive, raw, out, 3)
    assert (result["valid"], result["rejected"], result["duplicate"]) == (1, 1, 1)
    row = pq.read_table(out).to_pylist()[0]
    assert row["has_cvss"] and row["has_cpe"] and not row["has_cwe"]
    assert row["published_at"].utcoffset() == timedelta(0)
    assert json.loads(row["payload"]) == source
    with pytest.raises(DataError, match="authoritative record count"):
        bulk.normalize(archive, raw, out, 4)
    raw.write_bytes(gzip.compress(wrapper + b" "))
    with pytest.raises(DataError, match="decompressed size"):
        verify_archive(archive, raw, digest(raw.read_bytes()))


def test_cve_zip_preserves_adp_and_rejects_mismatched_member(tmp_path):
    record = {
        "cveMetadata": {
            "cveId": "CVE-2024-0001",
            "dateUpdated": "2024-01-02T00:00:00Z",
            "state": "PUBLISHED",
        },
        "containers": {
            "cna": {"affected": [{"vendor": "example", "versions": [{"version": "1.0"}]}]},
            "adp": [{"metrics": [{"other": {"type": "ssvc", "content": {"role": "test"}}}]}],
        },
    }
    raw = tmp_path / "official.zip"
    with ZipFile(raw, "w") as archive:
        archive.writestr("cves/2024/0xxx/CVE-2024-0001.json", json.dumps(record))
        archive.writestr("cves/2024/0xxx/CVE-2024-0002.json", json.dumps(record))
        archive.writestr("cves/deltaLog.json", "{}")
    archive = Archive("cve", "baseline", "https://example.test", "revision", PUBLISHED)
    output = tmp_path / "records.parquet"
    result = bulk.normalize(archive, raw, output, None)
    assert (result["available"], result["valid"], result["rejected"]) == (2, 1, 1)
    row = pq.read_table(output).to_pylist()[0]
    assert row["has_ssvc"] and row["has_adp"]
    assert json.loads(row["payload"])["containers"] == record["containers"]
    nested = tmp_path / "wrapped.zip"
    with ZipFile(nested, "w") as wrapper:
        wrapper.write(raw, arcname="cves.zip")
    assert bulk.normalize(archive, nested, output, 2) == result


def test_download_resumes_only_the_expected_provider_range(tmp_path):
    destination = tmp_path / "payload"
    destination.with_suffix(".part").write_bytes(b"abcd")

    def feed(request: httpx.Request) -> httpx.Response:
        assert request.headers["Range"] == "bytes=4-"
        return httpx.Response(206, headers={"Content-Range": "bytes 4-7/8"}, content=b"efgh")

    with httpx.Client(transport=httpx.MockTransport(feed)) as client:
        receipt = transfer(client, "https://example.test/archive", destination, 8, 8)
    assert receipt["sha256"] == digest(b"abcdefgh")
    assert destination.read_bytes() == b"abcdefgh"


def write_kev(root: Path, revision: str, day: int, records: list[dict]):
    archive = Archive(
        "kev", "catalog", "https://example.test/kev", revision, PUBLISHED + timedelta(days=day)
    )
    path = archive.folder(root)
    path.mkdir(parents=True)
    raw = path / "payload"
    raw.write_text(json.dumps({"vulnerabilities": records}))
    bulk.normalize(archive, raw, path / "records.parquet", len(records))
    write_json(
        path / "receipt.json",
        {
            "archive": {
                "source": "kev",
                "key": "catalog",
                "revision": revision,
                "published_at": archive.published_at.isoformat(),
            },
            "raw": {"retrieved_at": archive.published_at.isoformat()},
        },
    )


def test_kev_catalog_revisions_report_additions_changes_and_removals(tmp_path):
    def records(old_id: str, note: str):
        return [{"cveID": old_id}, {"cveID": "CVE-2024-0002", "notes": note}]

    write_kev(tmp_path, "old", 0, records("CVE-2024-0001", "a"))
    write_kev(tmp_path, "new", 1, records("CVE-2024-0003", "b"))
    with duckdb.connect() as db:
        [comparison] = bulk.kev_changes(db, tmp_path)
    assert [row["action"] for row in comparison["changes"]] == ["removed", "modified", "added"]


def test_modified_feed_stale_cursor_requires_annual_reconciliation(tmp_path):
    rows = [
        {"archive": {"key": "2025"}},
        {
            "archive": {"key": "modified", "published_at": PUBLISHED.isoformat()},
        },
    ]
    write_json(tmp_path / "nvd-index.json", rows)
    for days, expected in ((2, {2026}), (8, {2025, 2026})):
        modified = Archive(
            "nvd", "modified", "https://example.test", "sha", PUBLISHED + timedelta(days=days)
        )
        assert bulk.sync_years(tmp_path, {2025, 2026}, modified) == expected


def test_epss_day_index_is_idempotent_and_blocks_unexpected_date(tmp_path):
    calls = 0
    body = gzip.compress(b"cve,epss\nCVE-2020-0001,0.1\n")
    day = date(2021, 4, 14)

    def feed(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, content=body)

    with httpx.Client(transport=httpx.MockTransport(feed)) as client:
        first = bulk_epss.capture(client, tmp_path, day)
        again = bulk_epss.capture(client, tmp_path, day)
    assert calls == 1 and first["counts"]["valid"] == 1
    assert first["model_version"] == "v1"
    assert first["published_at"] is None
    assert first["counts"]["missing_percentile"] == 1
    assert again["cached"] and again["raw"]["sha256"] == first["raw"]["sha256"]
    with pytest.raises(DataError, match="requested score date"):
        bulk_epss.score_metadata("#model_version:v2,score_date:2022-02-05", date(2022, 2, 4))


def test_epss_daily_delta_requires_consecutive_dates_and_same_model(tmp_path: Path, capsys):
    for day, model, score in (
        (date(2022, 2, 4), "v2", 0.10),
        (date(2022, 2, 5), "v2", 0.25),
        (date(2022, 2, 7), "v2", 0.30),
        (date(2022, 2, 8), "v3", 0.81),
    ):
        content = gzip.compress(
            f"#model_version:{model},score_date:{day}\ncve,epss,percentile\n"
            f"CVE-2020-0001,{score},0.5\n".encode()
        )
        path = tmp_path / "raw.gz"
        path.write_bytes(content)
        bulk_epss.stage(
            tmp_path,
            day,
            path,
            {
                "bytes": len(content),
                "sha256": digest(content),
                "retrieved_at": PUBLISHED.isoformat(),
                "etag": None,
            },
            "https://example.test/epss",
        )
    bulk_epss.trend(tmp_path, "CVE-2020-0001", date(2022, 2, 4), date(2022, 2, 8))
    rows = json.loads(capsys.readouterr().out)["trend"]
    assert [row[-1] for row in rows] == [None, 0.15, None, None]
