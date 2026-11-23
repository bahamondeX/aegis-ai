"""Isolated synthetic ranks for ordering a score of zero and missing values."""

from pathlib import Path

from pipelines.query import Query, connect, query


def test_ranking_preserves_stable_ties_and_missing_epss(tmp_path: Path) -> None:
    with connect(tmp_path / "unit.duckdb", read_only=False) as db:
        db.execute("""
            CREATE TABLE dim_cve (
                cve_id VARCHAR, kev BOOLEAN, kev_added_at DATE, cvss_score DOUBLE,
                cvss_version VARCHAR, cvss_source VARCHAR, source_refs VARCHAR[]
            )
        """)
        db.execute("""
            CREATE TABLE fact_epss_latest (
                cve_id VARCHAR, epss DOUBLE, percentile DOUBLE, score_date DATE, source_ref VARCHAR
            )
        """)
        db.execute("""
            INSERT INTO dim_cve VALUES
                 ('CVE-2026-9004', true, DATE '2026-01-01', 10, NULL, NULL, []),
                 ('CVE-2026-9003', true, DATE '2026-01-01', NULL, NULL, NULL, []),
                 ('CVE-2026-9002', true, DATE '2026-01-01', 5, NULL, NULL, []),
                 ('CVE-2026-9001', true, DATE '2026-01-01', 5, NULL, NULL, [])
        """)
        db.execute("""
            INSERT INTO fact_epss_latest VALUES
                ('CVE-2026-9003', 0, 0, DATE '2026-01-02', 'synthetic'),
                ('CVE-2026-9002', 0, 0, DATE '2026-01-02', 'synthetic'),
                ('CVE-2026-9001', 0, 0, DATE '2026-01-02', 'synthetic')
        """)
        assert [row["cve_id"] for row in query(db, Query.RANKING, limit=4)] == [
            f"CVE-2026-900{index}" for index in (1, 2, 3, 4)
        ]
        assert len(query(db, Query.RANKING, min_epss=0, limit=4)) == 3
