SELECT source, status, row_count, coverage, source_date, retrieved_at, duration_ms, error_code
FROM ingestion_runs
ORDER BY source
