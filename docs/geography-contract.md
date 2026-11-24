# Geographic evidence and CVE detail contract

The G5 extension preserves all eight canonical Iceberg tables and their
historical manifests. Country context is a separately dated, digest-bound
companion to a pinned release. Its read scope is country only and ignores CVE,
severity, ranking, and date filters. Country geometry comes from Natural Earth.
Registration, operator presence and published coverage have different labels.
A country outline never represents confirmed site coordinates.

The authenticated `GET /v1/map` response adds a `geography_version` and
separate `network` and `exposure` metadata. The existing observation list
and envelope stay compatible. Until a qualified public-safe aggregation policy
exists, the new exposure view serves an empty observation list with an
unavailable reason. Measured zero requires an explicit source value with
known coverage, unit and time window. Sensor attempts and confirmed
incidents are separate categories. They stay disabled with this release.
The public-safe projection has no raw hosts, ASNs, exact locations or
private incidents. All existing data routes still require authentication.

The authenticated `GET /v1/cves/{cve_id}` adds one snapshot-bound detail read.
It returns global vulnerability attributes, source-bound affected product
conditions and mitigation evidence, with optional country-scoped exposure
separate from those global facts. CVSS, EPSS and KEV keep their original
definitions. An NVD CPE condition identifies a published applicability
criterion. Asset version, environment and installation require separate
confirmation. Raw archive object names and identifiers are internal only.

The existing investigation POST accepts an optional typed mitigation context
containing the selected CVE and source evidence IDs. It requires an explicit
matching snapshot and the exact selected CVE in filters. The existing
`get_vulnerabilities` tool accepts an optional singleton detail flag for this
path. The six tool names, four graph nodes, SSE version and event kinds
are unchanged. The researcher revalidates supplied IDs against the actual
selected row before resolving evidence. It reads global CVE attributes
separately from country exposure and never proposes an implicit scope change.
Source instructions are shown as citations after validation and kept out of
the model prompt. A handoff is editable client-side and never transmitted.

Current deployed AgentCore and Cognito remain on their verified versions.
The extension operates locally. Future cloud execution requires an
explicitly reviewed deployment of code and read scope, including carefully
limited access to the pinned source archive. No immutable storage format
or AWS policy is changed by this increment.
