# V2 official vulnerability ingestion

The V2 sources land beside the deployed MVP in the ignored local data
directory. Each source revision has an immutable compressed payload, a
normalized Parquet file, a download receipt and an ingestion receipt.
The data contract uses one source record per CVE for each artifact. The
complete source document remains in the Parquet payload column. Typed
identity, status, timestamps and enrichment-presence columns support
bounded audits without loading the full documents.

## Capture and synchronize

```sh
uv run --locked --no-sync python -m pipelines.bulk_vulnerabilities kev nvd cve --plan-only
uv run --locked --no-sync python -m pipelines.bulk_vulnerabilities kev nvd cve
uv run --locked --no-sync python -m pipelines.bulk_vulnerabilities kev nvd cve --sync-nvd
uv run --locked --no-sync python -m pipelines.kev_history
```

Use `--root` for a different volume. The bulk runner reserves 1 GiB of
available disk space. It bounds elapsed transfers and uncompressed input.
Downloads whose official archive size is pinned can resume at an exact
byte range. Files become visible only after size and checksum validation.
Existing receipts and files are rechecked before reuse. Capture errors
are reported for the affected archives and independently completed
archives remain available.

The current KEV JSON supplies a declared count. NVD feeds are checked
against the published uncompressed SHA-256 and size for every annual
partition and the modified feed. The denominator is the number of entries
in the verified vulnerability arrays. The CVE Program denominator is the
number of CVE record members in its size- and digest-verified official
baseline and same-day cumulative delta. The importer supports the wrapped
baseline ZIP and retains CNA and ADP documents, including SSVC assessments.
The normalized CVE data remains traceable to the exact original payload.
[NVD feed documentation](https://nvd.nist.gov/vuln/data-feeds) ·
[CVE List V5](https://github.com/CVEProject/cvelistV5)

The NVD index keeps annual partitions and recorded deltas. After a gap
longer than seven days it reconciles the annual partitions and the modified
feed. The current source view chooses one record per CVE using source
modification time and artifact publication time. Source-to-source matches
keep both original versions. Dates are compared in UTC. A timestamp
difference signals a source discrepancy for inspection.

CISA's historical command archives the official Git branch, emits
additions, modifications and removals, and retains source commit IDs and
catalog checksums. It appends new fast-forward segments and verifies old
segments before reusing them. A malformed upstream commit remains in the
raw archive and is identified in the report. The next valid comparison
records the intervening gap. [CISA KEV data branch](https://github.com/cisagov/kev-data)

## Local verification on 24 November 2026

| Source | Checked artifacts | Available and normalized records | Distinct CVEs after source-specific overlay |
| --- | --- | ---: | ---: |
| CISA KEV | Current catalog | 1,792 of 1,792 | 1,792 |
| NVD | 25 annual feeds through 2026 and the modified feed | 440,131 of 440,131 | 431,114 |
| CVE Program | Midnight baseline and same-day delta | 431,604 of 431,604 | 431,119 |

There were zero rejected records or intra-file duplicates in these captures.
The NVD and CVE Program sources matched on 431,100 IDs. NVD alone had 14 and
the CVE Program alone had 19. All KEV IDs joined to both. NVD lacked a CVSS
record for 23,307 current CVEs, a reported CWE identifier for 80,810 and
configuration evidence for 104,178. CVE Program records lacked ADP for
28,279 and SSVC for 204,815. These counts express upstream enrichment
availability.

Compressed official vulnerability captures totalled 931,312,814 bytes.
The normalized files totalled 400,761,872 bytes. The corrected command
reused the downloaded archives and completed in 52.02 seconds with
522,403,840 bytes maximum resident memory. A subsequent synchronization
reused the existing captures and reproduced the counts and overlap.
Evidence is under `data/evidence/v2/`.

The CISA mirror exposed 348 historical revisions from its first reachable
catalog on 2025-01-24 to 2026-11-23. Of those, 347 were valid and one was
truncated JSON. The resulting history recorded 1,796 additions, including
the initial catalog, 2,000 modifications and four removals. The first
reachable revision limits this historical coverage.

The NVD CPE Dictionary META advertised 85,357,131 compressed bytes and
915,206,817 uncompressed bytes. The separate match feed advertised
893,689,456 compressed bytes and 3,947,625,712 uncompressed bytes. The
dictionary is suitable for a separate streaming product-intelligence pilot.
The match feed needs a distinct storage and scan review. Neither artifact
was ingested in the vulnerability corpus check.
[CPE Dictionary META](https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.meta) ·
[CPE Match META](https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.meta)

## EPSS daily captures and historical backfill

```sh
uv run --locked --no-sync python -m pipelines.bulk_epss
uv run --locked --no-sync python -m pipelines.bulk_epss --archive-plan
uv run --locked --no-sync python -m pipelines.bulk_epss \
  --start 2021-04-14 --end 2021-05-13 --max-downloads 7
uv run --locked --no-sync python -m pipelines.bulk_epss \
  --start 2026-06-14 --end 2026-06-16 --trend CVE-1999-0001
```

The historical runner reads FIRST's official archive index, verifies each
listed blob, then writes a date-partitioned Parquet file and a checksum
receipt. Repeat a bounded command to resume the same date range. An
incomplete window exits nonzero and records the remaining listed dates.
An absent upstream date has a separate status. Earlier files that supply
probability alone have a null percentile. Daily probability change uses
consecutive dates under the same model. The actual June 2026 cutover
produced a null shift for the model transition and a measured zero on
the next date for the tested CVE. [FIRST EPSS data](https://www.first.org/epss/data)

The archive index from 2026-11-24 listed 2,041 dates from 2021-04-14
through 2026-11-23. Nine of the 2,050 calendar dates were absent from that
index. The verified local sample covered 43 of 2,041 available dates
(2.11%) and 6,477,173 score records. The latest file contained 411,399
valid scores. The first 30 calendar days had 25 available files and all
25 were captured. The sample preserved 1,637,480 v1 records with missing
source percentiles. All captured date reports had zero rejected or
duplicated records.

The index lists 2,812,440,549 bytes of raw archives. The verified sample
used 36,921,229 raw bytes and 57,651,956 Parquet bytes. Applying each
sample year's Parquet-to-raw ratio to that year's archive bytes projects
4.39 GB of Parquet and **7.20 GB total**. The host had 2.93 GB free at
measurement and the runner reserves 1 GiB. An EPSS-only destination needs
about 8 GiB free for the remaining archive and its working reserve.
The totals and dated gaps are recorded in
`data/evidence/v2/epss-storage-estimate.json` and
`data/v2/epss/archive-plan.json`.

## Planning estimates for cloud expansion

The measured vulnerability corpus and estimated full EPSS history total
about 8.54 GB before Iceberg metadata, staging, retention and results.
Use these examples to bound a future authorization. They assume S3
Standard at USD 0.023 per GB-month and Athena at USD 5 per decimal TB
scanned for calculation. Each query workload counts statements rather
than browser interactions.

| Scenario | Stored GB | Monthly Athena statements and average billed scan | S3 and Athena estimate per month |
| --- | ---: | --- | ---: |
| Validation | 10 | 1,000 × 10 MB | USD 0.28 |
| Bounded pilot | 25 | 10,000 × 32 MB | USD 2.18 |
| Growth | 100 | 100,000 × 32 MB | USD 18.30 |

Estimates cover storage and Athena scans. Price Glue, requests, KMS,
transfer, logs, Lambda, AgentCore and model inference for the approved
workload before deploying. Cloud read parity, compaction and scan
measurements are V2.5 acceptance cases.
[S3 pricing](https://aws.amazon.com/s3/pricing/) ·
[Athena pricing](https://aws.amazon.com/athena/pricing/)
