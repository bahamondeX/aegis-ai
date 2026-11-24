# AEGIS AI

AEGIS G1 is a local vulnerability intelligence pipeline. It captures CISA KEV and FIRST
EPSS, enriches up to 20 KEV CVEs per run from NVD, and publishes evidence-backed Parquet and
DuckDB views. The default query command prints aggregate results.

## Quickstart

Use native Apple Silicon, Python 3.12 via uv, and the toolchain reported by `make preflight`.
The Node and pnpm pins are for the later Nuxt work. The Python install uses `uv.lock`.
[Nuxt 3 requirements](https://nuxt.com/docs/3.x/getting-started/installation) ·
[pnpm compatibility](https://pnpm.io/installation)

```sh
make preflight
make bootstrap
make ingest-local
make validate-data
make query-local
make verify-phase1
make verify-phase1
```

Optional `NVD_API_KEY` and `SHODAN_API_KEY` may be set in the environment or a Git-ignored
`.env` with mode 600. See [.env.example](.env.example). Anonymous NVD access is supported.

Use `SNAPSHOT=<run-uuid>` with `validate-data`, `query-local`, `test` or `verify-phase1`
to pin a particular capture. For example, these two commands replay the same verified local run.

```sh
make verify-phase1 SNAPSHOT=4e13ca6b-c2e1-4407-88bc-c362da7dbacb
make verify-phase1 SNAPSHOT=4e13ca6b-c2e1-4407-88bc-c362da7dbacb
```

Verification runs Ruff, the isolated unit tests and integration tests against the real
captured feeds. It rebuilds Parquet and a fresh DuckDB from the pinned raw inputs and compares
SHA-256 values, counts and sampled results from all four SQL templates. Run
`uv run --locked --no-sync pytest -q tests/unit` for unit tests before a live capture exists.

## Verified snapshot from 2026-11-23

| Source | Published or response timestamp, UTC | Retrieved, UTC | Records and coverage |
|---|---|---|---|
| CISA KEV | 19:43:55.797900 | 23:44:35.206229 | 1,792 catalog CVEs |
| FIRST EPSS | 12:00:23 | 23:44:37.358988 | 411,399 daily scores, 1,792 of 1,792 KEV CVEs matched |
| NIST NVD 2.0 | 23:44:44.241000 | 23:44:44.351119 | 20 of 20 requested records returned, 40 CVEs enriched across two batches |
| Geographic exposure | Unknown | 23:44:44.813954 account check | Unavailable, 0 observations |

Of the 1,792 KEV CVEs, 40 had source-supplied CVSS and 1,752 had no NVD enrichment.
The relationship query found 5,016 edges, including 3,208 product edges and 1,808 CWE edges.
The five highest EPSS scores were all 0.99999, and 920 KEV entries scored at least 0.5.
Both pinned verification runs passed 22 tests (17 unit and 5 live-capture integration).

The [manifest](data/snapshots/4e13ca6b-c2e1-4407-88bc-c362da7dbacb/manifest.json)
records counts and Parquet checksums. The
[capture record](data/snapshots/4e13ca6b-c2e1-4407-88bc-c362da7dbacb/capture.json)
records fetch metadata, raw checksums and the NVD cursor. The
[gate log](data/evidence/verify-phase1-b.log), [aggregate queries](data/evidence/query-local.log)
and [execution record](STATUS.md) preserve the local verification evidence. Raw inputs,
Parquet, DuckDB and command logs live in the ignored `data/` directory. On a fresh checkout,
ingest live feeds to create a new local snapshot and ID.

## Data semantics

- The enrichment cursor ranks unvisited KEV CVEs by catalog addition date, EPSS and CVE ID.
  It rotates after the cohort is exhausted and carries forward earlier NVD enrichment by
  modification date. CVSS uses the newest reported version and prefers a primary metric
  within that version. The recorded NVD CPE paths point to the original applicability
  expressions, including any version bounds, logical operators and vulnerability flags.
  [NVD API documentation](https://nvd.nist.gov/developers/vulnerabilities)
- The EPSS fact table keeps one capture per score date. The ranking query joins the latest scores
  to the KEV cohort. The historical view includes all observed score dates. EPSS estimates
  exploitation likelihood over 30 days. The KEV catalog records known exploitation.
  [FIRST EPSS guidance](https://www.first.org/epss/using-epss) ·
  [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- The optional Shodan account check stores only capability flags. A generic country-facet
  probe is available when the free plan is confirmed. Country exposure stays unavailable
  without evidence for the cohort. [Shodan API documentation](https://developer.shodan.io/api)
- Publication writes the manifest after checking the staged snapshot. When NVD returns
  zero usable records, ingestion exits nonzero and keeps the partial capture. The active
  pointer advances only when the required feeds and at least one NVD record validate.
  DuckDB views reference local absolute Parquet paths.

KEV is CC0-1.0, with third-party links subject to their own terms.
[KEV license](https://github.com/cisagov/kev-data/blob/develop/LICENSE)

EPSS scores are produced by Empirical Security and maintained by the FIRST EPSS SIG.
[EPSS data and attribution](https://www.first.org/epss/data)

This product uses data from the NVD API but is not endorsed or certified by the NVD.

## G2 lakehouse

The [lakehouse runbook](docs/lakehouse.md) covers local CDK synthesis, the Linux ARM64
ingestion image, project-scoped deployment, Iceberg publication and Athena parity.
[STATUS.md](STATUS.md) records which checks have actually run.
