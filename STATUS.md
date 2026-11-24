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

## 2026-11-24T00:23:30Z — G2 local work and AWS gate blocker

Resumed from G1 commit `76360a7` and its verified snapshot
`4e13ca6b-c2e1-4407-88bc-c362da7dbacb`. The worktree was clean at startup. G2 adds
the Python CDK lake stack, locked ARM64 Lambda packaging, conditional EPSS capture
reuse, PyIceberg publication, a bounded Athena engine 3 adapter and guarded AWS
operations. Release manifests pin all eight Iceberg versions. The initial CDK
configuration keeps the six-hour schedule disabled until the first manual cloud
ingestion is verified.

### Executed checks

Wall times are from `/usr/bin/time -p`. Evidence paths below are relative to
`data/evidence/g2/`.

| Command | Exit | Wall time | Evidence |
|---|---:|---:|---|
| `make preflight` | 0 | 2.34 s | `preflight.log` |
| `make bootstrap` | 0 | 0.29 s | `bootstrap.log` |
| `make typecheck` | 0 | 0.56 s | `typecheck.log` |
| `uv run --locked --no-sync pytest -q tests/unit` | 0 | 3.26 s | `unit.log` |
| `make verify-phase1 SNAPSHOT=4e13ca6b-c2e1-4407-88bc-c362da7dbacb` | 0 | 12.58 s | `verify-phase1-final.log` |
| `make synth` | 0 | 18.68 s | `synth-final.log` |
| `make diff-local` | 0 | 16.30 s | `diff-local-final.log` |
| `env AEGIS_SCHEDULE_ENABLED=1 AEGIS_DATA_DIR=data/evidence/g2/schedule-enabled make synth` | 0 | 28.67 s | `synth-enabled.log` |
| `uv run --locked --no-sync python data/evidence/g2/check-assembly.py` | 0 | 1.44 s | `check-assembly.log` |
| `env PYTHONPATH="$PWD" uv run --locked --no-sync python data/evidence/g2/replay-two-releases.py` | 0 | 7.28 s | `replay-two-releases.log` |
| `docker buildx build --platform linux/arm64 --provenance=false --sbom=false --load --file infra/Dockerfile --tag aegis-ingest:g2 .` | 0 | 209.38 s | `image-build-b.log` |
| `docker run --rm --platform linux/arm64 --entrypoint /var/lang/bin/python -v "$PWD/data/evidence/g2/linux-live:/tmp/aegis" aegis-ingest:g2 -m pipelines.cli --data-dir /tmp/aegis ingest --env-file /tmp/aegis/no-dotenv` | 0 | 96.83 s | `linux-live-ingest.log` |

The final pinned verification passed Ruff and 27 tests, including 21 unit tests
and six real-capture integration tests. The local Iceberg test reused all eight
version IDs on an identical rerun, checked row counts and grain uniqueness, and
compared six query cases with DuckDB. The two-release rehearsal used the older
real capture `ffcdce0b-bc7f-452b-90a8-67a7f043540a` followed by the pinned snapshot.
It interrupted publication after the EPSS table commit, confirmed the prior
versions remained readable, and completed the new release without recommitting
EPSS or duplicating rows. The pre-existing empty geography table produced a
PyIceberg warning that its delete matched no records. Both releases had zero
observations and their counts verified. The independent local Linux ingestion
produced `a5334eda-a66c-4244-8a7e-67c305744bbf` with 1,792 real KEV entries, 411,399
EPSS scores, 20 out of 20 NVD enrichments and zero geographic observations. Its
raw captures and manifest are under `data/evidence/g2/linux-live/snapshots/`.

The local CDK assembly is in `data/cdk.out/`. Inspection verified both schedule
states, 18 CloudFormation resources per template, the engine 3 and 64 MiB workgroup
settings, private and encrypted buckets, retained TLS policies, the ARM64 Lambda
and its concurrency cap, and that the staged image context excluded credentials
and captured data. The offline diff used an empty template as its baseline.

### Failures and corrections

- The first `make synth` exited 2 after a JSII child-process failure. JSII rejected
  the shared cache because its parent directory had mode 0777. The command now
  disables the package cache for the project subprocess. The next synthesis
  and both final schedule variants exited 0. See `synth-a.log` and `synth-b.log`.
- The first Mypy check reported both `settings` and `infra.settings` for the same
  module. Added `infra/__init__.py`. The bounded project-source check then flagged
  seven annotation issues. Corrected those and ran `make typecheck` successfully
  over 19 source files. See `types-a.log` and `typecheck.log`.

### AWS gate

| Required check | Observed result |
|---|---|
| `make aws-preflight` | Exit 2. The operation exited 1 with `set AEGIS_AWS_ACCOUNT and AEGIS_AWS_REGION for the project`. |
| `make diff` | Exit 2 at the same project configuration guard. Only the offline diff ran successfully. |
| `make verify-cloud` | Exit 2 at the same guard. There are no Athena query IDs, scan timings or deployed resource IDs. |
| Deployment, bootstrap, SecureString sync, table initialization, local snapshot publish, cloud ingestion, destroy | The corresponding Make commands each exited 2 at the target guard. No cloud writes were issued. |

The AWS MCP connector's read-only STS check succeeded for an account ending in
`6271`. The terminal had only the `default` profile configured. No explicit AEGIS
account, region, profile or approved USD ceiling was supplied. The connector's STS
result does not identify an authorized project deployment target. See
`aws-preflight-guard.log`, `diff-guard.log`, `verify-cloud-guard.log` and the other
`*-guard.log` files.

**G2 remains BLOCKED.** The pending acceptance criteria are the live diff, deployment,
Glue-backed Iceberg and seed idempotence, manual cloud ingestion, Athena/DuckDB parity,
and verification of the deployed encryption settings and enabled scheduler. The
[runbook](docs/lakehouse.md) records the deployment and retention sequence and an
illustrative monthly estimate of $3.91 for N. Virginia under the stated workload.
No deployed spend or cleanup resulted from this run. With explicit account, region,
profile and budget authorization, resume at `make aws-preflight` and apply the
runbook's verified ordering.

## 2026-11-24T00:33:00Z — ARM64 packaging correction

The Linux snapshot query with networking disabled exited 1 because DuckDB could
not autoload ICU for its UTC setting. Packaging now installs the signed extension
for the locked DuckDB version and loads it during the build. The image uses a
fixed extension directory and disables runtime auto-installation.

- The first packaging correction used DuckDB with a custom HTTPS repository.
  It exited 1 because DuckDB could not bootstrap `httpfs` for that repository.
  See `image-build-icu.log`.
- The second attempted a direct HTTPS download from the Linux build stage. The
  request returned HTTP 403 and the build exited 1. See `image-build-icu-b.log`.
- The third used `INSTALL icu FROM core` and `LOAD icu`. The installation and
  signature check completed in the image build stage. See `image-build-icu-c.log`.
- A separate Lambda Runtime Interface Emulator check initially exceeded a 15-second
  request timeout. A 45-second check reached the handler and confirmed it rejected
  the invalid action. The emulator logged 17.86 seconds of local initialization.
  See `linux-final-entrypoint.log` and `linux-entrypoint-retry.log`.

Ruff and all 27 pinned-snapshot tests passed again with the extension-directory
support in place. `make verify-phase1 SNAPSHOT=4e13ca6b-c2e1-4407-88bc-c362da7dbacb`
exited 0 in 17.14 s and `make typecheck` exited 0 in 2.91 s. See
`verify-phase1-icu.log` and `typecheck-icu.log`.

`make synth`, `make diff-local`, enabled-schedule synthesis, and inspection of
both updated assemblies exited 0. The times were 38.62 s, 28.97 s, 38.62 s, and
0.57 s, respectively. See `synth-package-final.log`, `diff-package-final.log`,
`synth-enabled-package-final.log` and `check-assembly-package-final.log`.

The completed Linux ARM64 image `aegis-ingest:g2-icu` is
`sha256:aab248505aed4fe1d991d5e92759edc308d05fa4b85a5b2375b43406bb044c0c`.
The final command
`docker buildx build --platform linux/arm64 --provenance=false --sbom=false --load --file infra/Dockerfile --tag aegis-ingest:g2-icu .`
exited 0 in 355.31 s. The signed extension installation took 7.0 s in the build
step. See `image-build-icu-c.log` and `image-inspect-icu.log`.

The completed image revalidated and queried the real Linux capture with
`docker run --rm --platform linux/arm64 --network none --entrypoint /var/lang/bin/python -v "$PWD/data/evidence/g2/linux-live:/tmp/aegis:ro" aegis-ingest:g2-icu -m pipelines.cli --data-dir /tmp/aegis query --snapshot a5334eda-a66c-4244-8a7e-67c305744bbf`.
It exited 0 in 34.73 s, with 3,974 graph edges and zero geographic observations.
A separate network-disabled test using `--read-only --user 10001:10001 --tmpfs /tmp`
opened a DuckDB UTC connection and exited 0 in 7.03 s. See
`linux-icu-query.log` and `linux-icu-readonly.log`.

The first emulator call on the rebuilt image exited 1 with `Connection refused`
before the listener was ready. After adding a bounded listener check to the
local smoke script, `sh data/evidence/g2/smoke-entrypoint.sh aegis-ingest:g2-icu`
exited 0 in 14.77 s. The packaged ARM64 handler received the request and rejected
the invalid action as expected. See `linux-icu-entrypoint.log` and
`linux-icu-entrypoint-ready.log`.

The local G2 checks are complete. The last fully verified gate remains G1 while
AWS deployment and live G2 verification await the approved project settings.

## 2026-11-24T01:02:09Z — G2 resumed with authorization

The root `.env` contained an approval matching the explicit account ending in
`6271`, region `us-east-1`, prefix `aegis-dev`, profile `default`, and USD 15
ceiling. The file was mode 600 and ignored by Git. Added the local artifact path
and later the verified scoped bootstrap policy ARN while preserving existing
file bytes and the values of all prior entries. The Make CLI targets now use
Python dotenv parsing with an allowlist and explicit process overrides.

| Check | Exit | Observation |
|---|---:|---|
| `make aws-preflight` | 2 | The Botocore login credential provider required CRT. |
| `make aws-preflight` after adding the Boto3 CRT extra to the infra group | 0 | Terminal STS matched the configured account. 356 Lambda concurrency slots were unreserved. The project bootstrap was absent. |
| `env AEGIS_AWS_ACCOUNT=000000000001 make aws-preflight` | 2 | Live STS mismatch stopped preflight. |
| `env AEGIS_DEPLOY_APPROVAL= make deploy` | 2 | The approval guard stopped deployment. |
| `env AEGIS_BUDGET_USD=0 make deploy` | 2 | The budget guard stopped deployment. |
| `make lint`, `make typecheck`, `make verify-phase1` | 0 | 29 tests passed and the pinned snapshot replay matched the published fingerprints and query results. |
| `make synth`, `make diff` | 0 | Project-scoped synthesis and live diff completed. |
| `make prepare-bootstrap-policy` | 0 | Created the scoped policy in `/aegis/aegis-dev/`. IAM Access Analyzer flagged an invalid S3 action in the initial document. Removed it from the project policy before attachment, revalidated with zero IAM errors, and reran the target successfully. |

Evidence is under `data/evidence/g2-dotenv/`. AWS writes are scoped to the
approved deployment. G2 remains in progress. The next steps are project
bootstrap, the lake stack deployment, and cloud data verification.

## 2026-11-24T01:13:29Z — Initial cloud deployment failed and recovery prepared

- `make cdk-bootstrap` exited 0 in 79.39 s. The tagged project bootstrap
  stack `aegis-dev-bootstrap` reached `CREATE_COMPLETE`. A subsequent
  `make aws-preflight` exited 0 in 3.32 s and reported bootstrap version 34.
- `make deploy` exited 2 after 367.00 s. The ARM64 image was built and published
  to the dedicated ECR repository with digest
  `sha256:741122f181664c6a22c83f6aa74a91bad7258d7d37e981f619d6e55a993dee93`.
  CloudFormation could not associate the KMS key with the ingestion log group.
  Automatic rollback then failed because Scheduler required `DeleteSchedule`
  scoped to the schedule group even though it was empty. See `deploy-a.log`.
- AWS confirmed `aegis-dev-lake` is in `ROLLBACK_FAILED`. The surviving Scheduler
  group contains zero schedules, the retained Glue database contains zero
  tables, and the KMS key was retained. Cloud ingestion and Athena verification
  have yet to run.
- Added an explicit regional CloudWatch Logs grant scoped to the ingestion log
  group's encryption context. Updated the IAM policy to allow `DeleteSchedule`
  within the project group only. IAM Access Analyzer reported zero errors for
  policy version `v3`. Future CDK deployments preserve successful resources
  on failure.
- `make lint`, `make typecheck`, `make verify-phase1`, `make synth`, and
  `make diff` returned 0 after the corrections. The replay passed 29 tests
  in 6.83 s. Evidence is in the `*-recovery.log` files under
  `data/evidence/g2-dotenv/`.
- The read-only recovery inspection verified the retained resources are
  importable by Glue database name and KMS key ID. The prepared recovery
  script rejected execution without separate approval. Recovery would remove
  the failed stack and its empty scheduler group, then reattach the existing
  Glue database and KMS key before retrying deployment.

**G2 remains BLOCKED** pending explicit approval for failed-stack recovery.
Preserve the bootstrap stack, Glue database, and KMS key. With approval, complete
the guarded recovery, deploy with scheduling disabled, verify bootstrap and
Iceberg idempotence, publish the pinned snapshot twice, perform manual ingestion,
enable the scheduler, and verify both the pinned and latest Athena releases.
G3 local implementation follows G2 acceptance.
