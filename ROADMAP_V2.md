# AEGIS AI V2 roadmap

V2 extends the current AEGIS architecture and remains free to users. The
deployed release and its G1–G7 evidence remain pinned. G1–G5 are closed. The
combined production browser smoke passed, and the G6/G7 identity acceptance
items in [STATUS.md](STATUS.md) remain open. V2 public data is built locally
under the ignored data root. An expansion in AWS requires separately scoped
approval based on measured storage, request, scanning and inference costs.

## Baseline and execution order

The pinned release `4e13ca6b-c2e1-4407-88bc-c362da7dbacb` contains 1,792
KEV CVEs, 411,399 EPSS scores for one date, 40 cumulative NVD enrichments,
and the Canadian CRTC network-context companion. The current NVD runner
requests up to 20 KEV records per capture. Its data contracts and published
snapshot remain usable while new source-grain tables are developed.

| Milestone | Depends on | Acceptance evidence | Status |
| --- | --- | --- | --- |
| V2.1 Official vulnerability corpus | Pinned baseline and qualified source manifests | All accessible KEV, NVD year feeds and CVE List V5 members counted and reconciled. Preserve source documents, invalid and duplicate counts, CVE overlap, missing enrichments, KEV revision history, resumable deltas, and EPSS availability by date and model. | Local KEV, NVD and CVE Program baseline and synchronization verified. Current EPSS and 43 historical dates verified. Complete EPSS normalization needs a larger volume. |
| V2.2 Global network intelligence | A versioned country dimension and per-provider rights review | Preserve CRTC. Qualify RIR delegated data, IANA and RIPEstat, then CAIDA, PeeringDB, ITU and UN SDG, Cloudflare Radar and regulator data. Count at least 150 distinct supported countries or territories across qualified metrics. Record ASN registration and documented operational geography independently. | Local WDI/ITU coverage target met for the subscription indicator. The NRO audit verified coarse registration data across all five RIRs and 240 reported codes. Public terms and additional indicators remain in review. |
| V2.3 Shodan aggregate evidence | Scoped existing account, provider limits and reuse review | Document actual entitlement and coverage denominator. Cache only permitted coarse aggregate results. Compare authorized research exports and public alternatives when entitlement is limited. Record unavailable scope. | Account and field metadata verified. The `oss` plan did not meet the confirmed free-plan guard. Aggregate and redistribution entitlement remain unverified. |
| V2.4 Geographic reference layers | V2.2 and qualified association or exposure evidence | Blue network context, dashed or hatched purple inferred associations, amber observed exposure and isolated private verified sites. Require dual provenance for inference, label geographic basis, show confidence and methodology, and test unavailable versus measured zero. | Planned. CVE geography remains unavailable in production. |
| V2.5 Lakehouse expansion | Measured V2.1 and V2.2 workloads, V2.4 evidence grains, AWS approval | Reuse current Iceberg schemas where compatible. Verify incremental merges, manifest-last recovery, bounded Athena parity, partition pruning, file sizing, compaction and retention. Measure scheduler and Lambda continuation bounds before enabling them. | Planned. |
| V2.6 Knowledge graph and rankings | V2.1 and V2.5 | Trace CVE, CWE, CPE, applicability, KEV, EPSS, CVSS, SSVC and mitigation links to source evidence. Exercise paged graph filters. Validate independent ranking views for each metric. | Planned. |
| V2.7 Agent and MCP | V2.4 through V2.6 and existing authorization | Extend the four-node graph with typed reads. Measure at least 95% grounded claims with an explicit denominator. Verify source distinction, affected versions, evidence quality, manufacturer remediation, replay, cancellation and access isolation. | Planned. |
| V2.8 Command center | Stable typed API across V2.5 through V2.7 | Verify catalog paging, historical charts, worldwide context and coverage, independent layers, explainable methodology, graph exploration, responsive layouts and real browser performance. Preserve the design system. | Planned. |
| V2.9 Private organizational risk | V2.5 and explicit operator approval | Optional CycloneDX or SPDX ingestion with encrypted, isolated data and applicability checks. Potential product matches remain distinct from confirmed affected assets. | Optional. |

## V2.1 local increments

1. Retain current CISA KEV metadata and every record field. Track successive
   snapshots by content digest. Compare source records by CVE ID to report
   additions, revisions and removals. Measure historical coverage against
   available captures and official repository releases.
2. Download NIST compressed feeds for every advertised annual partition,
   including the through-2002 partition, and reconcile the published
   uncompressed size and digest. Stream records into Parquet batches.
   Use the modified feed for synchronization inside its eight-day window.
   Reconcile annual metadata after a longer gap. Evaluate the official CPE
   dictionary separately before adding CPE dimensions.
3. Pin an official CVE List V5 midnight asset and its latest same-day
   cumulative delta. Preserve CNA and ADP containers, including CISA
   Vulnrichment and SSVC where present. Reconcile IDs with NVD while keeping
   each source's complete document. Retain both revisions when values differ.
4. Capture the latest EPSS scores and measure bounded historical samples
   starting with 2021-04-14 and published model cutovers. Use the score date
   and CVE as the fact grain. Persist a receipt for each date, report gaps, and
   avoid conflating model shifts with changes in individual vulnerabilities.
   Estimate complete archive size and free space before expanding the backfill.

For each capture report upstream partitions or members, downloaded files,
valid normalized records, rejected records, duplicates, matches, missing
enrichments and historical dates. Record upstream manifests, payload digests,
normalized sizes, elapsed time, peak RSS and evidence paths. Measure identity
and cost separately from data quality. Source coverage does not imply complete
severity, product, weakness or EPSS enrichment.

## Cross-milestone release checks

Keep the existing snapshot and evidence contracts backward compatible.
Before each new serving release, check referential integrity, deterministic
replay, source discrepancies, incremental recovery, DuckDB/Athena parity,
auditable geographic basis, entitlement, data reuse, and workspace isolation.
Report query time, peak memory, Parquet bytes, Athena scanned bytes,
model usage and cost against a measured workload. Review monthly pilot and
growth scenarios before any expanded publication. Use existing resources and
bounded continuations with no always-on compute.

Public geographic views use country or region aggregates. Inference requires
a genuine source-backed CVE-to-network association and separate geography
evidence. A network total cannot become a country exposure count. Gray means
unavailable, the outline legend identifies measured zero, severity uses red,
and stars mark user highlights. Keep observed exposures, network associations,
sensor activity, private findings and confirmed incidents distinct.

[NVD feeds](https://nvd.nist.gov/vuln/data-feeds) ·
[CVE List V5 releases](https://github.com/CVEProject/cvelistV5/releases) ·
[FIRST EPSS archive](https://www.first.org/epss/data)
