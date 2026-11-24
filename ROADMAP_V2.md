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

| Increment | Depends on | Acceptance evidence | Status |
| --- | --- | --- | --- |
| V2-A Cloud ingestion foundation | Verified local V2 artifacts and existing project ownership | Immutable Bronze keys, verified object checksums and versions, exact-scope approval, durable attempt receipts, resumable migration and a direct worker canary. | AWS migration and ARM64 canary passed. The imported date and replay reused receipts. The worker published one new verified date. |
| V2-B Historical data platform | V2-A plus scoped AWS authorization | Existing corpus migrates without redownload. Reconcile the archive, valid dates, absent dates and remediated failures. Size CPE Dictionary and CPE Match independently. | Official vulnerability artifacts are in S3. 44 EPSS dates verified in AWS. Remaining digest-pinned windows are the next step. |
| V2-C Iceberg and analytical marts | Versioned, committed Bronze inputs | Use source-grain facts and release-pinned Gold. Measure DuckDB/Athena parity, history, scan bytes, cache and publication recovery. | Two-date EPSS staging Silver and daily Gold verified in AWS with DuckDB/Athena parity and date pruning. Full history and remaining marts are pending. |
| V2-D Geographic intelligence | V2-C for serving and approved source provenance | Serve WDI/ITU and CRTC separately. RIR registration is distinct from operating location. Conditional inferred/observed layers require qualified evidence. | Global local context verified. Public rights and geography layers remain qualified separately. |
| V2-E Interactive globe | Bounded geography contracts | Verify zoom, rotation, fullscreen, accessible resize and aggregate selection in Chromium. | Planned. |
| V2-F CVE intelligence overlay | V2-C profile and evidence contract | Reuse one profile from map, graph, ranking, timeline and investigation. Verify bounded provenance and mitigation workflows. | Planned. |
| V2-G Temporal command center | V2-C analytical dates and V2-E interactions | Verify model transitions, missing periods, source granularity, comparison and historical globe synchronization. | Planned. |
| V2-H Agentic analytics | Typed read-only serving contracts | Extend the four-node graph and typed UI commands with a measured 95% grounding threshold and authorized read isolation. | Planned. |
| V2-I Production release | Applicable authorization and V2-A through H gates | Record AWS resources and costs, canary tests, rollback, browser screenshots, latency and privacy checks. | Pending. |
| V2-J Private organizational intelligence | Separate scope and user-authorized inventory | Optional CycloneDX or SPDX ingestion with encrypted data and explicit applicability evidence. | Optional. |

The first serving checkpoint is an EPSS history projection built from
committed date receipts. Frontend dependencies follow bounded serving
contracts and measured source availability. Shodan's observed `oss` plan
and zero credits remain recorded. Positive CVE geography needs a qualifying
source and is independent of pipeline implementation.

[Cloud ingestion architecture](docs/v2-cloud-lakehouse.md) ·
[Cloud cost proposal](docs/v2-cost-model.md)

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
