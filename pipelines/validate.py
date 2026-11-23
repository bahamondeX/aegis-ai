from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import duckdb
import pyarrow.parquet as pq

from pipelines.io import DataError, capture_for, file_digest, snapshot_directory
from pipelines.query import Query, connect, query
from schemas.sources import Run
from schemas.tables import GRAINS, TABLES

ORPHANS = {
    "product CVE": """
        SELECT 1 FROM bridge_cve_product b ANTI JOIN dim_cve c USING (cve_id)
    """,
    "product": """
        SELECT 1 FROM bridge_cve_product b ANTI JOIN dim_product p USING (product_id)
    """,
    "product evidence": """
        SELECT 1 FROM bridge_cve_product b
        JOIN dim_product p USING (product_id)
        ANTI JOIN evidence e
        ON b.evidence_id = e.evidence_id AND b.cve_id = e.source_record_id AND p.source = e.source
    """,
    "CWE CVE": """
        SELECT 1 FROM bridge_cve_cwe b ANTI JOIN dim_cve c USING (cve_id)
    """,
    "CWE evidence": """
        SELECT 1 FROM bridge_cve_cwe b ANTI JOIN evidence e
        ON b.evidence_id = e.evidence_id AND b.cve_id = e.source_record_id AND b.source = e.source
    """,
    "EPSS evidence": """
        SELECT 1 FROM fact_epss f ANTI JOIN evidence e
        ON f.source_ref = e.evidence_id AND e.source = 'epss'
        AND f.score_date = CAST(e.source_date AS DATE)
    """,
    "geography evidence": """
        SELECT 1 FROM fact_geo_exposure f ANTI JOIN evidence e
        ON f.evidence_id = e.evidence_id AND f.source = e.source
    """,
    "geography CVE": """
        SELECT 1 FROM fact_geo_exposure f ANTI JOIN dim_cve c USING (cve_id)
    """,
    "CVE evidence": """
        SELECT 1 FROM dim_cve c CROSS JOIN UNNEST(c.source_refs) AS r(ref)
        ANTI JOIN evidence e
        ON r.ref = e.evidence_id AND c.cve_id = e.source_record_id AND e.source IN ('cisa', 'nvd')
    """,
}

INVALID_ROWS = {
    "CVE identity, dates or evidence": """
        SELECT 1 FROM dim_cve WHERE NOT regexp_full_match(cve_id, 'CVE-[0-9]{4}-[0-9]{4,}')
        OR NOT kev OR kev_due_at < kev_added_at OR kev_ransomware_use NOT IN ('Known', 'Unknown')
        OR length(source_refs) NOT BETWEEN 1 AND 2 OR length(list_distinct(source_refs)) !=
        length(source_refs) OR (published_at IS NULL) != (modified_at IS NULL)
        OR (published_at IS NULL) != (length(source_refs) = 1)
    """,
    "CVSS range or metadata": """
        SELECT 1 FROM dim_cve WHERE cvss_score NOT BETWEEN 0 AND 10
        OR (cvss_score IS NULL) != (cvss_version IS NULL)
        OR (cvss_score IS NULL) != (cvss_source IS NULL)
        OR (cvss_score IS NULL) != (cvss_vector IS NULL)
        OR (cvss_score IS NULL AND severity IS NOT NULL)
        OR cvss_version NOT IN ('2.0', '3.0', '3.1', '4.0')
        OR (cvss_score IS NOT NULL AND published_at IS NULL)
    """,
    "EPSS range or CVE": """
        SELECT 1 FROM fact_epss WHERE epss NOT BETWEEN 0 AND 1 OR percentile NOT BETWEEN 0 AND 1
        OR NOT regexp_full_match(cve_id, 'CVE-[0-9]{4}-[0-9]{4,}')
    """,
    "CWE identity or attribution": """
        SELECT 1 FROM bridge_cve_cwe
        WHERE NOT regexp_full_match(cwe_id, 'CWE-[0-9]+') OR length(attributed_to) = 0
    """,
    "CPE relationship": """
        SELECT 1 FROM bridge_cve_product b
        JOIN dim_product p USING (product_id) JOIN dim_cve c USING (cve_id)
        WHERE (p.source = 'nvd' AND (p.cpe IS NULL OR b.configuration_refs IS NULL
            OR length(b.configuration_refs) = 0 OR c.nvd_configurations_json IS NULL
            OR b.relation_type != 'nvd_cpe_match'))
            OR (p.source = 'cisa' AND (p.cpe IS NOT NULL OR b.configuration_refs IS NOT NULL
            OR b.relation_type != 'kev_catalog_product'))
    """,
    "geography range": """
        SELECT 1 FROM fact_geo_exposure WHERE NOT regexp_full_match(country_iso2, '[A-Z]{2}')
        OR "count" < 0 OR confidence NOT BETWEEN 0 AND 1 OR coverage NOT BETWEEN 0 AND 1
    """,
    "coverage range": """
        SELECT 1 FROM ingestion_runs WHERE coverage NOT BETWEEN 0 AND 1
        OR row_count < 0 OR duration_ms < 0
    """,
    "evidence checksum or dates": """
        SELECT 1 FROM evidence
        WHERE NOT regexp_full_match(checksum, '[a-f0-9]{64}')
        OR NOT regexp_full_match(evidence_id, '[a-f0-9]{64}')
        OR source_date > retrieved_at + INTERVAL '10 minutes'
    """,
}


def count(db: duckdb.DuckDBPyConnection, statement: str) -> int:
    row = db.execute(statement).fetchone()
    if row is None:
        raise DataError("expected aggregate row")
    return int(row[0])


def check_freshness(run: Run) -> None:
    for source, age in (("cisa", 21), ("epss", 2), ("nvd", 3)):
        capture = capture_for(run.captures, source)
        if capture is None or capture.source_date is None:
            if source == "nvd":
                continue
            raise DataError(f"{source}: missing publication date")
        delta = capture.retrieved_at - capture.source_date
        if delta > timedelta(days=age) or delta < timedelta(minutes=-10):
            raise DataError(f"{source}: publication date outside capture freshness window")
    epss = capture_for(run.captures, "epss")
    if epss is None or epss.source_date is None or epss.source_date.date() != max(run.epss_history):
        raise DataError("epss: current score date regressed")


def validate(root: Path, folder: Path, run: Run) -> dict[str, Any]:
    check_freshness(run)
    fingerprints = {}
    for name, spec in TABLES.items():
        path = folder / "parquet" / f"{name}.parquet"
        file = pq.ParquetFile(path)
        if file.schema_arrow != spec:
            raise DataError(f"{name}: unexpected Arrow schema")
        fingerprints[name] = file_digest(path)
    with connect(folder / "aegis.duckdb") as db:
        for name, keys in GRAINS.items():
            group = ", ".join(keys)
            if db.sql(
                f"SELECT 1 FROM {name} GROUP BY {group} HAVING COUNT(*) > 1 LIMIT 1"
            ).fetchone():
                raise DataError(f"{name}: duplicate grain")
            required = [field.name for field in TABLES[name] if not field.nullable]
            predicate = " OR ".join(f'"{column}" IS NULL' for column in required)
            if db.sql(f"SELECT 1 FROM {name} WHERE {predicate} LIMIT 1").fetchone():
                raise DataError(f"{name}: required field is null")

        for check, statement in {**ORPHANS, **INVALID_ROWS}.items():
            if db.execute(f"SELECT 1 FROM ({statement}) AS invalid LIMIT 1").fetchone():
                raise DataError(f"data check failed: {check}")

        check_evidence(root, db)
        counts = {name: count(db, f"SELECT COUNT(*) FROM {name}") for name in TABLES}
        summary = join_summary(db, run, counts)
        graph = query(db, Query.GRAPH, limit=1)
        if not graph:
            raise DataError("relationship graph is empty")
        if counts["fact_geo_exposure"] != 0 or query(db, Query.GEO):
            raise DataError("unsupported exposure facts in G1")
    return {"row_counts": counts, "join_coverage": summary, "parquet_sha256": fingerprints}


def check_evidence(root: Path, db: duckdb.DuckDBPyConnection) -> None:
    evidence_files = db.sql("""
        SELECT DISTINCT raw_snapshot, raw_file, checksum, uri, license, retrieved_at, source
        FROM evidence
    """).fetchall()
    for snapshot, raw_file, checksum, uri, license_, retrieved_at, source in evidence_files:
        source_folder = snapshot_directory(root, UUID(snapshot))
        archived = Run.model_validate_json((source_folder / "capture.json").read_bytes())
        capture = capture_for(archived.captures, source)
        if capture is None or (
            capture.raw_file,
            capture.checksum,
            capture.uri,
            capture.license,
            capture.retrieved_at,
        ) != (raw_file, checksum, uri, license_, retrieved_at):
            raise DataError(f"{source}: evidence differs from capture metadata")
        raw = source_folder / "raw" / raw_file
        if raw.parent != source_folder / "raw" or file_digest(raw) != checksum:
            raise DataError(f"{source}: evidence checksum or path mismatch")


def join_summary(
    db: duckdb.DuckDBPyConnection,
    run: Run,
    counts: dict[str, int],
) -> dict[str, Any]:
    row = db.sql("""
        SELECT COUNT(*), COUNT(e.epss), COUNT(c.published_at), COUNT(c.cvss_score),
               MAX(e.epss), COUNT(*) FILTER (WHERE e.epss >= 0.5)
        FROM dim_cve c LEFT JOIN fact_epss_latest e USING (cve_id)
    """).fetchone()
    if row is None:
        raise DataError("analysis cohort summary missing")
    joined, matched, nvd_count, cvss_count, max_epss, above_threshold = row
    latest_epss = count(db, "SELECT COUNT(*) FROM fact_epss_latest")
    if joined != counts["dim_cve"] or not matched or not latest_epss:
        raise DataError("empty or fan-out KEV/EPSS join")
    coverage = {entry["source"]: entry for entry in query(db, Query.COVERAGE)}
    if set(coverage) != {"cisa", "epss", "nvd", "shodan"} or (
        coverage["cisa"]["row_count"],
        coverage["epss"]["row_count"],
        coverage["nvd"]["row_count"],
        coverage["shodan"]["row_count"],
    ) != (joined, latest_epss, len(run.nvd_found), 0):
        raise DataError("source coverage counts do not reconcile")
    if (
        coverage["epss"]["coverage"] != matched / joined
        or coverage["nvd"]["coverage"] != len(run.nvd_found) / len(run.requested_nvd)
        or coverage["shodan"]["status"] != "unavailable"
    ):
        raise DataError("source coverage ratios or geography status do not reconcile")
    return {
        "kev_cves": joined,
        "kev_with_epss": matched,
        "kev_without_epss": joined - matched,
        "latest_epss_rows": latest_epss,
        "kev_with_nvd": nvd_count,
        "kev_with_cvss": cvss_count,
        "nvd_requested": len(run.requested_nvd),
        "nvd_returned": len(run.nvd_found),
        "nvd_missing": len(set(run.requested_nvd) - set(run.nvd_found)),
        "highest_kev_epss": max_epss,
        "kev_epss_at_least_0_5": above_threshold,
    }
