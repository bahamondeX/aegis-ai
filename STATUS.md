# AEGIS AI status

## 2026-11-23T23:31:29Z

G1 started. The repository had an initialized Git directory with no commits, the three
project instructions, and an existing local dotenv file. No prior status or data artifacts
were present. Host is Darwin ARM64 with Python 3.12.9, uv 0.7.19 and AWS CLI v2.
Restricted the existing dotenv file to mode 600 and excluded it from Git.

## 2026-11-23T23:40:14Z

The first complete snapshot passed ingestion at
`data/snapshots/ffcdce0b-bc7f-452b-90a8-67a7f043540a/`. It contained 20 NVD records.
These corrections preceded the successful ingestion.

| Command | Exit | Observed issue and correction | Evidence |
|---|---:|---|---|
| Direct `pipelines.fetch.run_capture` probe | 0 | HTTP 200 NVD batch was provisionally marked `source_schema`. The validation error concerned additive `ssvcV203` entries. The parser now selects the CVSS groups and decoded all 20 records in the saved response. | `data/snapshots/08416b86-ba73-4338-a28b-3d47d9d63902/capture.json` |
| `make ingest-local` | 2 | `ModuleNotFoundError: No module named 'pytz'` during DuckDB timestamp conversion. Added the dependency to `uv.lock`, ran `make bootstrap`, and reran ingestion. | `data/snapshots/4a4037b6-1d66-404a-9898-3c5897eae6c6/capture.json` |

Inspection of the EPSS header showed a full timestamp. The final capture preserves it
verbatim in UTC and uses its calendar date as the fact key.

## 2026-11-23T23:45:23Z — G1 PASS

Pinned snapshot `4e13ca6b-c2e1-4407-88bc-c362da7dbacb`. Every command with a snapshot
argument below used that ID. Timing is elapsed wall time reported by `/usr/bin/time -p`.

| Started UTC | Command | Exit | Elapsed | Evidence under `data/evidence/` |
|---|---|---:|---:|---|
| 2026-11-23 23:44:33 | `make ingest-local` | 0 | 11.55 s | `ingest-local.log` |
| 2026-11-23 23:45:12 | `make preflight` | 0 | 1.28 s | `preflight.log` |
| 2026-11-23 23:45:13 | `make bootstrap` | 0 | 0.04 s | `bootstrap.log` |
| 2026-11-23 23:45:13 | `make validate-data SNAPSHOT=…` | 0 | 1.15 s | `validate-data.log` |
| 2026-11-23 23:45:14 | `make query-local SNAPSHOT=…` | 0 | 0.86 s | `query-local.log` |
| 2026-11-23 23:45:15 | `make test SNAPSHOT=…` | 0 | 2.44 s | `test.log` |
| 2026-11-23 23:45:17 | `make verify-phase1 SNAPSHOT=…` | 0 | 3.05 s | `verify-phase1-a.log` |
| 2026-11-23 23:45:21 | `make verify-phase1 SNAPSHOT=…` | 0 | 2.93 s | `verify-phase1-b.log` |

Both verification runs passed Ruff, 17 unit tests and 5 integration tests against live
captures. Each rebuilt a fresh DuckDB from the same raw inputs. All eight Parquet checksums,
row counts and sampled results of four query templates matched. The preflight observed
Node 22.13.1, pnpm 12.23.0 on PATH, and AWS CLI 2.40.3. pnpm 10.32.1 is the deferred
frontend pin.

| Source | Source timestamp in UTC | Retrieval timestamp in UTC | Coverage |
|---|---|---|---|
| CISA KEV | 2026-11-23T19:43:55.797900Z | 2026-11-23T23:44:35.206229Z | 1,792 entries |
| FIRST EPSS | 2026-11-23T12:00:23Z | 2026-11-23T23:44:37.358988Z | 411,399 scores, 1,792 KEV matches, 0 unmatched |
| NVD CVE API | 2026-11-23T23:44:44.241000Z | 2026-11-23T23:44:44.351119Z | 20 requested, 20 returned, 0 missing |
| Shodan account status | Unknown | 2026-11-23T23:44:44.813954Z | HTTP 200 account lookup, `free_plan_unconfirmed` |

| Canonical table | Rows |
|---|---:|
| `dim_cve` | 1,792 |
| `fact_epss` | 411,399 |
| `dim_product` | 1,834 |
| `bridge_cve_product` | 3,208 |
| `bridge_cve_cwe` | 1,808 |
| `fact_geo_exposure` | 0 |
| `evidence` | 1,833 |
| `ingestion_runs` | 4 |

The NVD cursor advanced from 20 to 40 distinct CVEs across two real runs with zero
overlap. The second run retained a single EPSS partition for 2026-11-23. Forty KEV CVEs
had NVD enrichment and CVSS. The remaining 1,752 were outside the processed batches.
The highest EPSS was 0.99999, 920 KEV CVEs had EPSS ≥ 0.5, and the graph contained
5,016 edges. The country query returned an empty list and coverage was unavailable.

Find the immutable raw captures under
`data/snapshots/4e13ca6b-c2e1-4407-88bc-c362da7dbacb/raw/`. The same directory contains
`capture.json`, `manifest.json`, `parquet/` and `aegis.duckdb`. The files are local
and ignored by Git.

G1 has no open required blockers. Geographic exposure is conditional and remains
unavailable. G2 is pending. Its first planned command is `make aws-preflight` after
implementing the G2 preflight in a subsequent session.
