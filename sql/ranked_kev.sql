SELECT c.cve_id, c.kev, c.kev_added_at, c.cvss_score, c.cvss_version, c.cvss_source,
       e.epss, e.percentile, e.score_date, c.source_refs, e.source_ref AS epss_evidence_id
FROM dim_cve AS c
LEFT JOIN fact_epss_latest AS e ON e.cve_id = c.cve_id
WHERE c.kev AND (? IS NULL OR e.epss >= ?)
ORDER BY c.kev DESC, e.epss DESC NULLS LAST, c.cvss_score DESC NULLS LAST, c.cve_id
LIMIT ?
