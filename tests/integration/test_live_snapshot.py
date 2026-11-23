"""Exercises a pinned capture from make ingest-local against the real providers."""

import json
import os
from pathlib import Path
from uuid import UUID

import duckdb
import pytest

from pipelines.io import DataError, read_raw, selected_snapshot
from pipelines.normalize import required_capture
from pipelines.parse import parse_epss, parse_kev, parse_nvd
from pipelines.publish import load_run, validate_published
from pipelines.query import Query, connect, query
from schemas.sources import Run

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def live() -> tuple[Path, Path, Run]:
    root = Path(os.environ.get("AEGIS_DATA_DIR", "data")).resolve()
    selector = os.environ.get("AEGIS_SNAPSHOT")
    folder = selected_snapshot(root, UUID(selector) if selector else None)
    return root, folder, load_run(folder)


@pytest.fixture(scope="module")
def db(live: tuple[Path, Path, Run]):
    with connect(live[1] / "aegis.duckdb") as connection:
        yield connection


def test_real_counts_and_coverage(live: tuple[Path, Path, Run]) -> None:
    root, folder, run = live
    manifest = validate_published(root, folder)
    assert manifest["status"] == "ok"
    kev = parse_kev(read_raw(folder, required_capture(run, "cisa")))
    epss_capture = required_capture(run, "epss")
    published, _, epss = parse_epss(read_raw(folder, epss_capture))
    assert epss_capture.source_date == published
    summary = manifest["join_coverage"]
    assert kev.count == summary["kev_cves"]
    assert published.date() == max(run.epss_history)
    assert epss.height == summary["latest_epss_rows"]
    assert summary["kev_with_epss"] == len(
        {r.cveID for r in kev.vulnerabilities} & set(epss["cve"])
    )
    assert summary["kev_with_epss"] + summary["kev_without_epss"] == kev.count


def test_nvd_real_bounded_page_has_traceable_evidence(
    live: tuple[Path, Path, Run], db: duckdb.DuckDBPyConnection
) -> None:
    _, folder, run = live
    capture = required_capture(run, "nvd")
    _, records = parse_nvd(read_raw(folder, capture), run.requested_nvd)
    assert 1 <= len(records) <= len(run.requested_nvd) <= 20
    assert set(records) == set(run.nvd_found)
    assert set(run.requested_nvd) <= set(run.cursor)
    linked = db.sql("""
        SELECT e.source_record_id, e.source_date, c.cvss_score
        FROM evidence e JOIN dim_cve c ON e.evidence_id = ANY(c.source_refs)
        WHERE e.source = 'nvd'
    """).fetchall()
    by_id = {cve_id: (modified, score) for cve_id, modified, score in linked}
    for cve_id, record in records.items():
        assert by_id[cve_id][0] >= record.lastModified
        if by_id[cve_id][0] == record.lastModified:
            preferred = record.metrics.preferred()
            assert by_id[cve_id][1] == (preferred.cvssData.baseScore if preferred else None)
    assert db.sql("""
        SELECT COUNT(*) FROM dim_cve WHERE published_at IS NULL AND (
            cvss_score IS NOT NULL OR modified_at IS NOT NULL OR nvd_configurations_json IS NOT NULL
        )
    """).fetchone() == (0,)


def test_ranking_stable_null_last_and_bound_filter(db: duckdb.DuckDBPyConnection) -> None:
    rows = query(db, Query.RANKING, limit=1000)
    assert rows
    assert len({row["cve_id"] for row in rows}) == len(rows)

    def sort_key(row: dict) -> tuple:
        return (
            not row["kev"],
            -row["epss"] if row["epss"] is not None else float("inf"),
            -row["cvss_score"] if row["cvss_score"] is not None else float("inf"),
            row["cve_id"],
        )

    assert sorted(rows, key=sort_key) == rows
    assert query(db, Query.RANKING, min_epss=0.5, limit=1000) == [
        row for row in rows if row["epss"] is not None and row["epss"] >= 0.5
    ]
    with pytest.raises(DataError, match="threshold"):
        query(db, Query.RANKING, min_epss=float("nan"))
    with pytest.raises(DataError, match="limit"):
        query(db, Query.GRAPH, limit=1001)


def test_cpe_graph_preserves_match_paths_and_cwe_edges(db: duckdb.DuckDBPyConnection) -> None:
    assert query(db, Query.GRAPH, limit=5)
    rows = db.sql("""
        SELECT c.nvd_configurations_json, p.cpe, b.configuration_refs
        FROM bridge_cve_product b JOIN dim_cve c USING (cve_id)
        JOIN dim_product p USING (product_id) WHERE p.source = 'nvd'
    """).fetchall()
    for configurations, criteria, refs in rows:
        for ref in refs:
            assert ref.startswith("/configurations/")
            fields = ref.removeprefix("/configurations/").split("/")
            conf, node, match = (int(fields[index]) for index in (0, 2, 4))
            config = json.loads(configurations)[conf]
            entry = config["nodes"][node]["cpeMatch"][match]
            assert entry["criteria"] == criteria
            assert isinstance(entry["vulnerable"], bool)
            assert entry["matchCriteriaId"]
    assert db.sql("SELECT COUNT(*) FROM bridge_cve_cwe").fetchone()[0] > 0


def test_empty_geo_and_history(db: duckdb.DuckDBPyConnection) -> None:
    assert query(db, Query.GEO) == query(db, Query.GEO, country_iso2="PE") == []
    with pytest.raises(DataError, match="country"):
        query(db, Query.GEO, country_iso2="' OR 1=1")
    coverage = {row["source"]: row for row in query(db, Query.COVERAGE)}
    assert coverage["shodan"]["status"] == "unavailable"
    assert coverage["shodan"]["coverage"] is None
    assert coverage["shodan"]["row_count"] == 0
    assert db.sql("SELECT COUNT(DISTINCT score_date) FROM fact_epss_latest").fetchone() == (1,)
    assert (
        db.sql("SELECT COUNT(*) FROM fact_epss_history").fetchone()[0]
        >= db.sql("SELECT COUNT(*) FROM fact_epss_latest").fetchone()[0]
    )
