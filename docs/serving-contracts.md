# V2 analytical serving contracts

## Verified staged reads

The authenticated `/v2/catalog` route and `get_catalog` MCP tool read a
release-pinned, year-sharded mart in S3. Filters accept a catalog year,
exact CVE ID or stable cursor within a year, with a maximum of 100 rows.
The response includes the Silver snapshot as an opaque string. The catalog
summarizes source presence and coverage flags. See source-grain Silver for
values that disagree across captures.

The authenticated `/v2/network` route and `get_global_network_context` MCP
tool read one annual WDI/ITU observation per economy. Each response carries
the release, year, unit, source publication and applicable denominator.
Provider codes retain a nullable canonical geometry identifier. Missing
values remain null and measured zero stays explicit. These metrics describe
subscriptions and remain independent of CVE geography.

The implemented local canary exposes a version-pinned EPSS history read
through the CLI. Bronze and Silver receipts remain operator-scoped. The
existing deployed API and its eight-table release continue using the
current contracts.

## First planned production serving slice

| Read | Required response and bounds |
| --- | --- |
| Catalog and CVE profile | Compatible release ID, validated effective filters, bounded cursor page, source coverage and evidence IDs. Preserve independent source assessments and nullable enrichments. |
| CVE history | Compatible release ID, selected interval, source granularity, model versions, explicit gap and unscored states, limits and selected evidence. Clamp all historical computation to the release. |
| Globe and regional summary | Compatible release ID, observation type, coverage, precise unit, geography basis and source versions. Cap aggregates and page CVE lists. |
| Relationships and mitigation | Bounded typed relationship expansion and provenance. Keep cited manufacturer guidance, applicability and cleanup review separate from side-effect execution. |
| Source coverage and job status | Measured source denominator, freshness, provenance, count categories and job states. Private operational identifiers require administrative access. |

Use release-aware cache keys with applicable authorization scope. Server
handlers must preserve approved-session and workspace validation. The API
returns authorized evidence IDs; credentials, raw S3 identifiers and arbitrary
SQL remain internal. Cursor tokens bind the snapshot, effective filters,
query and authorization scope. Separate cache and raw query metrics.
Qualify proposed V2 endpoints before reusing or extending compatible V1
routes.

MCP tools stay typed, bounded and read-only. The existing four-node
orchestration and SSE command validation must be preserved. The agent
distinguishes measured facts, derived metrics, inferred references and
unavailable scope. New UI commands respect user overrides and cannot
execute arbitrary browser code.

The component canary is a local validation lane. Enabling these reads in
FastAPI, MCP or the hosted command center requires the combined serving
release, cloud parity measurements and browser isolation checks.
