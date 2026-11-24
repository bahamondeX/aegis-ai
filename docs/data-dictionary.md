# V2 data dictionary

Schema versions are independent of source revision and physical Iceberg
snapshot identity. Public projections require an auditable, compatible
release. Restricted raw artifacts and operational receipts remain private.

## Implemented canary objects

| Entity | Grain and logical key | Provenance, nulls and visibility |
| --- | --- | --- |
| Bronze source payload | Source, artifact class and SHA-256 | Exact source bytes and private license context. Content is immutable. S3 object version, size and full checksum are recorded remotely. |
| Bronze migration manifest | Approved inventory SHA-256 | Original relative artifact identities, content keys and verified object references. Private operational data. |
| Bronze EPSS date receipt | Score date and upstream Git blob fingerprint | Daily source identity, license, model, publication timestamp when present, validated counts and raw/normalized object references. |
| Bronze EPSS attempt receipt | Plan digest, score date and attempt | Attempt reservation, maximum bytes, state and measured outcome where available. An interrupted attempt can have a start without a completion. Private operational data. |
| Silver `fact_epss_daily` v1 | One CVE ID and score date per pinned Iceberg snapshot | `cve_id`, `score_date`, `model_version` and `epss` are required. `percentile` is nullable for source records without it. `evidence_key` identifies the private original artifact. Published query scopes must resolve associated evidence IDs under authorization. |
| EPSS component manifest v1 | Source plan, table identity and committed normalized date versions | Iceberg snapshot ID, schema version, date interval, per-day row counts and absent dates implied by the pinned plan. Private serving metadata. |

The Silver canary uses Iceberg format version 2, date identity partitions,
Zstandard compression, CVE ordering within a day and a 64 MiB file target.
It appends new dates or replaces only a changed date. One verified daily
partition is processed at a time. The component manifest advances only
after count validation. Keep snapshots referenced by published components;
any expiration requires a release-reference check. The MVP
`fact_epss` table and eight-table release use their current schemas.

## Planned source-grain and serving contracts

| Logical entity | Proposed grain and key | Boundary |
| --- | --- | --- |
| CVE, product, vendor, CPE, CWE, network operator, ASN, source, region, country and EPSS-model dimensions | Source-specific identifier or stable reconciled identity | Alias conflicts remain source-specific and evidence-linked. Workspace and provider scope follow the source. |
| CVE source revision, CVSS, SSVC and KEV history | Source, record, revision and assessment key when applicable | Publication and modification retain distinct meanings. Only observed severity and applicability revisions can appear in a timeline. |
| CVE relationships | Source and revision with two typed entity IDs and relation | Preserve applicability expressions. Product membership is evidence for a potential relationship. |
| Network context, inference and observed exposure | Source, scope, observation category, geography basis, unit and interval | Separate factual measurements and inferred references. Shared unknowns are nullable. Internal association IDs stay restricted. |
| Mitigation evidence | Source, advisory revision, CVE and applicability | Fixed versions and workarounds require evidence. Source guidance stays available independently of change proposals. |
| Quality and ingestion facts | Source artifact or job attempt and measured time | Distinguish source denominator, accepted, rejected, failed, pending and upstream-absent. |
| Gold profile, history, globe series, rankings and graph | Release and the bounded query grain | Derived views cite source facts and disclose effective filters, units, dates and coverage. |

Choose physical tables, partitions and ordering from measured scan and
update workloads. Daily partitions favor incremental replacement and
global date pruning. Monthly partitions with clustered CVE ordering or
hash buckets need a separate comparison for long single-CVE histories.
Keep duplicate metric units in separate observation categories.

The first local Gold projection, `mart_epss_global_daily`, is keyed by
component and score date. It includes the source model, observed count,
missing-percentile count, count with probability at least 0.95, mean,
median and p95. Every row uses the same global EPSS population and
model for that date. Days without source observations have no derived
row. The manifest binds the file to the Silver snapshot and its SHA-256.
