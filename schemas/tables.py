import pyarrow as pa

UTC_TIMESTAMP = pa.timestamp("us", tz="UTC")
TEXT = pa.string()
TEXTS = pa.list_(TEXT)
DATE = pa.date32()
INT = pa.int64()
FLOAT = pa.float64()


def required(name: str, dtype: pa.DataType = TEXT) -> pa.Field:
    return pa.field(name, dtype, nullable=False)


TABLES: dict[str, pa.Schema] = {
    "dim_cve": pa.schema(
        [
            required("cve_id"),
            required("description"),
            pa.field("published_at", UTC_TIMESTAMP),
            pa.field("modified_at", UTC_TIMESTAMP),
            pa.field("cvss_score", FLOAT),
            pa.field("cvss_version", TEXT),
            pa.field("cvss_source", TEXT),
            pa.field("cvss_vector", TEXT),
            pa.field("severity", TEXT),
            required("kev", pa.bool_()),
            required("kev_added_at", DATE),
            required("kev_due_at", DATE),
            required("kev_ransomware_use"),
            required("source_refs", TEXTS),
            pa.field("nvd_configurations_json", TEXT),
        ]
    ),
    "fact_epss": pa.schema(
        [
            required("cve_id"),
            required("score_date", DATE),
            required("epss", FLOAT),
            required("percentile", FLOAT),
            required("source_ref"),
        ]
    ),
    "dim_product": pa.schema(
        [
            required("product_id"),
            required("vendor"),
            required("product"),
            pa.field("cpe", TEXT),
            required("source"),
        ]
    ),
    "bridge_cve_product": pa.schema(
        [
            required("cve_id"),
            required("product_id"),
            required("evidence_id"),
            required("relation_type"),
            pa.field("configuration_refs", TEXTS),
        ]
    ),
    "bridge_cve_cwe": pa.schema(
        [
            required("cve_id"),
            required("cwe_id"),
            required("evidence_id"),
            required("source"),
            required("attributed_to", TEXTS),
        ]
    ),
    "fact_geo_exposure": pa.schema(
        [
            required("cve_id"),
            pa.field("country_iso2", TEXT),
            required("snapshot_at", UTC_TIMESTAMP),
            required("source"),
            required("scope"),
            pa.field("count", INT),
            required("unit"),
            pa.field("confidence", FLOAT),
            pa.field("coverage", FLOAT),
            required("evidence_id"),
        ]
    ),
    "evidence": pa.schema(
        [
            required("evidence_id"),
            required("source"),
            required("source_record_id"),
            required("retrieved_at", UTC_TIMESTAMP),
            required("source_date", UTC_TIMESTAMP),
            required("checksum"),
            required("uri"),
            required("license"),
            required("raw_snapshot"),
            required("raw_file"),
        ]
    ),
    "ingestion_runs": pa.schema(
        [
            required("run_id"),
            required("source"),
            required("status"),
            required("row_count", INT),
            pa.field("coverage", FLOAT),
            pa.field("cursor", TEXTS),
            required("duration_ms", INT),
            pa.field("error_code", TEXT),
            pa.field("source_date", UTC_TIMESTAMP),
            pa.field("retrieved_at", UTC_TIMESTAMP),
        ]
    ),
}

GRAINS: dict[str, tuple[str, ...]] = {
    "dim_cve": ("cve_id",),
    "fact_epss": ("cve_id", "score_date"),
    "dim_product": ("product_id",),
    "bridge_cve_product": ("cve_id", "product_id", "evidence_id"),
    "bridge_cve_cwe": ("cve_id", "cwe_id", "evidence_id"),
    "fact_geo_exposure": ("cve_id", "country_iso2", "snapshot_at", "source", "scope"),
    "evidence": ("evidence_id",),
    "ingestion_runs": ("run_id", "source"),
}
