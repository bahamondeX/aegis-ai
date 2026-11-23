WITH observations AS (
    SELECT cve_id, country_iso2, snapshot_at, source, scope, "count", unit, confidence,
           coverage, evidence_id,
           ROW_NUMBER() OVER (
               PARTITION BY cve_id, country_iso2, source, scope, unit
               ORDER BY snapshot_at DESC, evidence_id
           ) AS recency
    FROM fact_geo_exposure
    WHERE country_iso2 IS NOT NULL AND (? IS NULL OR country_iso2 = ?)
)
SELECT cve_id, country_iso2, snapshot_at, source, scope, "count", unit, confidence,
       coverage, evidence_id
FROM observations
WHERE recency = 1
ORDER BY country_iso2, cve_id, source, scope, unit
LIMIT ?
