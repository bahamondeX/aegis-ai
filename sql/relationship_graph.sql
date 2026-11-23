WITH edges AS (
    SELECT b.cve_id, b.relation_type, p.product_id AS target_id, p.product AS target_label,
           p.vendor, b.evidence_id
    FROM bridge_cve_product AS b
    JOIN dim_product AS p ON b.product_id = p.product_id
    UNION ALL
    SELECT cve_id, 'classified_as', cwe_id, cwe_id, CAST(NULL AS VARCHAR), evidence_id
    FROM bridge_cve_cwe
)
SELECT cve_id, relation_type, target_id, target_label, vendor, evidence_id
FROM edges
ORDER BY cve_id, relation_type, target_id, evidence_id
LIMIT ?
