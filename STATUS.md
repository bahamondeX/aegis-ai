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

## 2026-11-24T01:49:43Z — Scoped recovery authorized and executed

The explicit recovery authorization matched the existing STS account ending in
`6271`, `us-east-1`, profile `default`, and USD 15 ceiling. The temporary
recovery approval was scoped to the command. The root `.env` was kept at mode 600.

- `make aws-preflight` exited 0 in 4.47 s and verified bootstrap version 34.
- The guarded recovery initially exited 1 before deletion because Scheduler
  included three CloudFormation-managed tags in addition to the project tags.
  The check was tightened to require their exact stack ID, stack name and logical
  ID. The retry revalidated the failed stack and retained key and catalog and
  confirmed zero schedules and zero Glue tables immediately before deletion.
- The retry removed the failed stack and empty Scheduler group. CloudFormation
  rejected the subsequent import request because an IMPORT change set cannot
  add tags or an execution role. The import-only retry in
  `data/evidence/g2-resume/import_retained.py` imported exactly the existing Glue
  database and KMS key, verified their unchanged physical IDs, and applied
  the ownership tags and original scoped role in a separate stack update.
  The import-only command exited 0 in 144.34 s.
- `make synth` and live `make diff` exited 0 in 13.11 s and 13.92 s. The
  corrected deployment began with scheduling disabled. The project parameter
  metadata baseline contained zero parameters. No secret was overwritten.

Evidence is in `data/evidence/g2-resume/`. Cloud data verification remains pending.

## 2026-11-24T02:04:37Z — G2 PASS

All logs are under `data/evidence/g2-resume/`. Commands used the verified STS
target in `us-east-1` and the USD 15 authorization guard.

| Check | Exit | Time | Evidence |
|---|---:|---:|---|
| Corrected `make deploy` with scheduling disabled | 0 | 183.73 s | `deploy-disabled.log`, `scheduler-disabled.log` |
| Two `make init-tables` runs | 0 / 0 | 16.05 / 20.28 s | `init-first.log`, `init-second.log` |
| Two `make publish-local` runs | 0 / 0 | 57.91 / 50.49 s | `publish-first.log`, `publish-second.log`, `seed-idempotence.log` |
| `make ingest-cloud` | 0 | 36.25 s | `manual-ingest.log` |
| Enable-only `make diff` and `make deploy` | 0 / 0 | 14.31 / 56.68 s | `diff-enable.log`, `deploy-enable.log` |
| Scheduler delivery and publication | 0 | 68.39 s | `scheduler-delivery.log` |
| Deployed IAM, Scheduler trust, KMS log encryption and preserved image | 0 | 7.15 s | `permissions.log` |
| `make verify-cloud` | 0 | 42.72 s | `verify-pinned.log` |
| `make verify-cloud SNAPSHOT=df7e10ce-724b-452e-93b1-3b61d77a273f` | 0 | 411.10 s | `verify-manual.log` |
| `make verify-cloud LATEST=1` | 0 | 330.92 s | `verify-latest.log` |

The pinned release `4e13ca6b-c2e1-4407-88bc-c362da7dbacb` reused the same eight
Iceberg snapshot IDs on republish. Manual ingestion released
`df7e10ce-724b-452e-93b1-3b61d77a273f`. After that success, only the Scheduler
setting changed in the root `.env`. EventBridge emitted one delivery attempt
and the Lambda log confirmed publication of scheduled release
`9df91d1b-ae90-4cf4-81b8-32912e77b356`. All three releases compared every
canonical table's row count and unique grains and six read results against
DuckDB. Each had 1,792 KEV CVEs, 411,399 EPSS facts for the November 23 score
date, and zero geographic observations. Maximum observed Athena query time
was 4.60 s. The slower manual and scheduled checks included downloading and
revalidating their raw and Parquet archives.

The live checks verified the 64 MiB Athena cutoff, engine 3, encrypted result
storage, released v2 metadata, and Lambda ARM64 with reserved concurrency 1.
Role-principal simulation reported an Organizations denial that conflicted with
the already successful worker calls. Independently simulated the complete
deployed inline policy documents, confirmed ten expected allowed and denied
cases, and verified the live Scheduler trust policy. The dedicated bootstrap
and prior image digest remained in place. The original Glue database and KMS
key were reused, and SSM metadata was unchanged. The active stack,
workgroup, Lambda and schedule are `aegis-dev-lake`, `aegis-dev`,
`aegis-dev-ingest` and `aegis-dev/aegis-dev-feed-refresh`. The existing
runbook documents retention and the workload estimate. Final billed cost was
not measured.

G3 local API and MCP implementation is next.

## 2026-11-24T02:13:23Z — G3 PASS locally

Implemented FastAPI and the official MCP Streamable HTTP server over one
validated snapshot. REST uses seven routes and MCP exposes six typed read or
proposal tools. The DuckDB reader uses bound values, a five-second query
interrupt, and two concurrent read slots. The Athena adapter compiles the same
allowlisted read shapes against pinned Iceberg versions. Read results carry the
snapshot, EPSS score date, and source coverage. Geographic queries report
unavailable coverage instead of substituting global CVEs.

REST data endpoints and MCP require a signed bearer token for the configured
workspace. The local mode checks loopback and verifies issuer, audience,
expiry, and workspace. The development target generates a short-lived token
in a Git-ignored file with mode 600. The application supports HTTPS JWKS
configuration when supplied with an authorized issuer. The local verification
used signed loopback credentials. The Athena adapter's additional G3 query
shapes were verified by renderer unit tests. The live Athena parity recorded
under G2 covers the G2 queries and deployed lakehouse.

| Check | Exit | Time | Evidence under `data/evidence/g3/` |
|---|---:|---:|---|
| `make bootstrap` | 0 | 0.14 s | `bootstrap.log` |
| `make lint` | 0 | 0.09 s | `lint-final.log` |
| `make typecheck` | 0 | 0.72 s | `typecheck-final.log` |
| `make test` | 0 | 9.92 s | `test.log` |
| `make smoke-local` | 0 | 4.30 s | `smoke-final.log` |
| `make verify-phase1` | 0 | 10.00 s | `verify-phase1.log` |
| Isolated `make dev PORT=…` harness | 0 | 4.16 s | `dev.log` |

The test suite passed 32 tests. The smoke made real HTTP requests to the
loopback server and used the official MCP client for discovery and all six
tool calls over Streamable HTTP. It checked the selected snapshot with 1,792
KEV CVEs, evidence retrieval, stable ranking, invalid filters and excess
limits, cross-workspace rejection, token expiry and audience, and unavailable
geography. The development harness verified an authenticated KPI request and
then terminated its own Make process, which reported signal exit 143 as
expected during harness cleanup.

The first smoke exited 1 because its client used a keyword argument unsupported
by `httpx.Headers.update`. Corrected the header assignment and reran the
transport successfully. The first `make test` and `make verify-phase1` attempts
exited 2 on duplicate pytest module names. Renamed the unit module and reran
both with exit 0. Raw evidence and credentials are excluded from Git.

G3 is complete for local verification. Investigation streaming and live
Bedrock integration belong to G4.

## 2026-11-24T02:54:04Z — G4 locally verified, live gate blocked

Resumed from G2 commit `a63a46f` and G3 commit `ff203dd`. The four-node
LangGraph uses the six authenticated MCP tools and the pinned release
`4e13ca6b-c2e1-4407-88bc-c362da7dbacb`. The Validator renders claims only
from matching evidence, including the EPSS score date and references.
Bedrock can select existing claims by key. Each run has a bounded
checkpoint and SSE journal scoped to its authenticated owner. The G5
TypeScript client validates the same wire schema and preserves manual
filter edits when investigation events arrive.

The local evidence directory is `data/evidence/g4/`. Durations below are
for the stated commands or the HTTP stream measurement as identified.

| Verification | Exit / outcome | Evidence |
| --- | --- | --- |
| `make lint` and `make typecheck` | 0 each, 59 formatted Python files and 39 checked source modules | `lint-final.log`, `typecheck-final.log` |
| `make test` | 0, 55 passed in 8.38 s of pytest time | `make-test-final.log` |
| `make verify-phase1` | 0, 55 passed and pinned Parquet hashes and sampled query results reproduced in 16.45 s wall time | `phase1-final.log` |
| `make smoke-local` | 0, 7 authenticated REST routes and 6 MCP tools in 4.45 s | `g3-smoke-final.log` |
| `make smoke-investigation` | 0, first event 7.56 ms, report and terminal 428.76 ms | `investigation-final.log` |
| `make smoke-agent-local` | 0, first event 5.69 ms, report and terminal 433.76 ms | `runtime-final.log` |
| G4 isolated evaluation `pytest -q tests/unit/test_investigations.py` | 0, 21 passed. Includes grounding, allowlisted tool routing, unavailable geography, tenant and user isolation, malformed model output, throttling, timeout recovery, cancellation, durable replay, and encrypted conditional S3 writes. | `eval-final.log` |
| Frozen pnpm install, strict type check, tests, registry audit | 0 each, four TypeScript client tests passed and the audit reported no known vulnerabilities | `frontend-type-final.log`, `frontend-test-final.log`, `frontend-audit.log` |
| `python -m scripts.verify_frontend_stream` | 0, compiled client received 10 real events, first at 32.74 ms and complete at 573.61 ms. It applied the authorized proposal and its matching analytics atomically. | `frontend-live-final.log` |
| G2 local `make synth` | 0, existing lakehouse stack still synthesizes | `g2-synth.log` |
| `make synth-agent`, `cfn-lint 1.60.1`, `cfn-guard 3.2.1` | 0 each, including private KMS checkpoint, TLS, retention, JWT, separate approval and lifetime rules | `synth-agent-final.log`, `cfn-lint.log`, `cfn-guard.log` |
| Local synthesized image build and Docker `--network none` loopback smoke | 0 each, Linux ARM64, UID 10001, 1,107,288,808 bytes. First event 47.81 ms and completion 845.47 ms with the real read-only snapshot and matching Linux DuckDB ICU extension. | `docker-build-final.log`, `docker-runtime-smoke.log` |
| `AEGIS_BEDROCK_APPROVAL= make smoke-investigation BEDROCK=1` | 2 at the scoped approval guard, as expected | `bedrock-guard.log` |

Each G4 smoke observed 10 ordered events, 8 claims supported by 8 retrieved
evidence IDs, a typed filter proposal, exact cursor replay and one terminal
event. The unsupported regional investigation emitted zero claims and
zero filter proposals. A Peru investigation emitted no observations,
ranked CVEs or risk summary because the coverage was unavailable.
The model adapter unit test used a stubbed SDK
response to exercise token accounting. Live inference latency and token
usage are unavailable pending authorization.

### Additional live Athena parity

Ran `uv run --locked --no-sync python -m scripts.verify_g3_athena` with
exit 0 in 27.61 s. STS matched the configured default AWS profile,
account ending 6271 and region `us-east-1`. The workgroup enforced its
64 MiB cutoff. The verification matched six DuckDB cases, including the
filtered KPI and ranking, exact CVE and date scope, empty regional map,
12 graph edges and provenance on the same Iceberg release. Seven queries
scanned 10,210,468 bytes. The longest Athena query was 6,224 ms. The
verification capped itself at eight queries with an estimated maximum
scan charge of $0.00268435, within the $15 ceiling under the earlier
$5.45 G2 operating scenario. These are scan and operating estimates.
The current account invoice balance was unavailable. Query IDs and
per-query data are in `athena-g3.log`.

### Corrections and remaining gate

The first SSE smoke failed on MCP host-header validation with HTTP 421.
An explicit loopback Host fixed the official transport. One evaluation
collection attempt failed because pytest reserves the parameter name
`request`. Renaming it allowed the tests to run. The Node 22.13.1 bundled
Corepack could not match the registry signature. A pinned Corepack 0.34.6
runner verified the pnpm 10.32.1 release. A browser-stream TypeScript error
was corrected by decoding chunks incrementally. The final loops above passed.

The AWS control plane confirmed Nova Micro `amazon.nova-micro-v1:0`
active and authorized for in-region text inference in `us-east-1`.
The no-charge CountTokens probe returned a ValidationException because
Nova Micro does not support that API. See `model-control.log`. Model
selection, rate settings and the independent budget ledger are configurable.

**G4 live gate remains BLOCKED on separate Bedrock authorization.**
After approval, run the live Converse smoke and record the actual tokens,
latency, cited report and terminal event. The AWS AgentCore deployment
also requires its separate authorization and an approved OIDC configuration.
The local template and image checks verify packaging and configuration.
Cloud change-set validation, deployed JWT behavior and remote streaming
remain pending. The bounded follow-up estimates are $0.021504 for Bedrock
and approximately $0.48 for AgentCore and supporting resources
([cost details](docs/g4-investigations.md)). The proposed ceilings are
$5 for each service and $15 remains the existing lakehouse ceiling.

G5 preparation delivered the framework-neutral SSE and visualization
state modules. Nuxt 3's documented maintenance period ended on 2026-07-31.
The full dashboard, browser tests and G5 acceptance remain pending.

## 2026-11-24T03:18:31Z — G4 PASS with live Bedrock

Resumed from commit `78f0f9e`. STS confirmed account ending 6271, region
`us-east-1`, the default profile and the `aegis-dev` scope. Persisted the
$5 Bedrock and $5 AgentCore approvals, with independent local and runtime
inference allocations of $0.05 each. The existing $15 lake authorization
remains active. The root dotenv file is Git-ignored at mode 600.

| Verification | Exit | Outcome |
| --- | --- | --- |
| `make smoke-investigation BEDROCK=1` (initial) | 0 | Six cited claims after a bounded revision. 1,014 input and 184 output tokens over two Nova Micro calls at 847 and 624 ms. First SSE event 8.30 ms, completion 2,428.31 ms. Estimated cost $0.000061250. |
| `make smoke-investigation BEDROCK=1` (cancellation loop) | 0 | Four cited claims, 507 input and 73 output tokens, measured invocation path 1,012 ms. First SSE event 13.38 ms, completion 1,728.73 ms. Active cancellation reached one terminal event. Estimated cost $0.000027965. |
| `AEGIS_BEDROCK_BUDGET_USD=.000001 uv run --locked --no-sync python -m backend.cli smoke-investigation --bedrock --expect-fallback` | 0 | The reservation was refused before inference. Eight grounded fallback claims, zero usage entries, first SSE event 13.88 ms and completion 877.20 ms. The on-disk allocation was preserved. |
| `make lint`, `make typecheck`, `make test` | 0 each | 55 Python tests passed. SDK stubs verified throttling and timeout recovery. The live provider logs show no throttle response. |

The live cases checked cited evidence, scoped routing, replay and terminal
event ordering against the real pinned release. The Peru investigation
reported unavailable exposure and omitted the risk summary and global
ranking. Latencies for inference include the local reservation path.
Evidence is under `data/evidence/g4-live/` in `converse-first.log`,
`converse-final.log`, `budget-fallback.log` and `regression.log`.

An unquoted reporting heredoc reran two authorized live smokes and one
no-inference fallback smoke. Their three recorded outputs are preserved
in `reporting-reruns.jsonl`. Across all four successful live investigations,
Converse recorded 2,535 input and 403 output tokens, estimated at
$0.000145145. The formatting command was corrected before commit.

## 2026-11-24T03:42:10Z — G5 PASS on Nuxt 4

Migrated the architecture to Nuxt 4.7.0, Nuxt UI 4.13.1, Tailwind CSS
4.3.0, native Node 22.22.3 and pnpm 10.32.1. Verified the downloaded
Apple Silicon Node archive against its published SHA-256. The dashboard
uses the existing authenticated API and pinned real release. The
globe, MapLibre tactical view, evidence-bound deck.gl overlay,
Cytoscape graph and ECharts EPSS chart are client-side. Charts,
ranked CVEs and relationship drill-downs share the authenticated view.

| Verification | Exit | Result |
| --- | --- | --- |
| `make lint-ui` and `make typecheck-ui` | 0 each | ESLint and Nuxt strict TypeScript |
| `sh scripts/frontend.sh test` | 0 | Four SSE and filter-state tests |
| `make build-ui` | 0 | Production Nuxt build completed in 6.27 s. Client chunks totaled 7.76 MB, 2.53 MB gzip. Visualization chunks load on demand. Vite reported its 500 kB chunk-size warning. |
| `make smoke-ui` | 0 | Two Chromium tests in 16.9 s on the production build. Verified the desktop and mobile layouts, real KPI response, rendered map and graph, evidence drawer, live SSE, applied proposal and unavailable Peru scope. |
| `uv run --locked --no-sync python -m scripts.smoke_dashboard --cognito` | 0 | One additional Chromium test in 27.8 s, before the final map and display refinements. Verified hosted Cognito Authorization Code with S256 PKCE, memory-only tokens, direct live AgentCore SSE through the Nuxt proxy, and an actual Bedrock report. |
| `sh scripts/frontend.sh audit` | 0 | No known vulnerabilities after pinning the affected nested minimatch dependency to 11.0.1. |
| `make verify-phase1` | 0 | 56 Python regression tests passed. Real snapshot replay reproduced the same Parquet hashes and sampled query results. |

Evidence is under `data/evidence/g5/`. Inspected `desktop.png`,
`tactical.png`, `investigation.png`, `evidence.png`, `mobile.png`,
`mobile-sources.png` and `cognito-agentcore.png`. The first browser
loop accepted a blank tactical canvas. Added an explicit MapLibre worker
asset, fixed the map container height, and required rendered country features
and a visible map viewport in Playwright. Inspected the corrected
screenshot. Geographic exposure on the selected release stays unavailable,
and the map renders only the contextual outlines. The desktop browser
confirmed that applying the investigation proposal refreshed the ranked
table to three rows while synchronizing the graph and KPIs.

The dashboard ran locally in production mode. Frontend hosting and a
standalone cloud API are outside the authorized deployment.

## 2026-11-24T03:43:05Z — Authorized AgentCore portion of G6 PASS

The scoped identity and runtime stacks both reached `CREATE_COMPLETE`.
No existing AEGIS-specific OIDC provider was found. The dedicated
Cognito pool uses administrator-only registration, a public OAuth
authorization-code client, 10-minute access tokens and a workspace group.
The backend checks issuer, expiry, app client, token type and group.
The native Nuxt authorization request used S256 PKCE and kept the
access and refresh tokens out of browser storage. All three temporary
validation users were disabled after their checks.

| Verification | Exit | Result |
| --- | --- | --- |
| `python -m infra.agent_deploy identity` | 0 | Reviewed change set created the scoped pool, browser client, domain and workspace group. |
| `python -m infra.agent_deploy runtime` | 0 on retry | Published a Linux ARM64 image to the existing project ECR repository and deployed the AgentCore runtime, role and private checkpoint bucket. The initial change set treated the bootstrap version value as an SSM key. The retry used the template's scoped SSM reference. |
| `cfn-lint` against both synthesized templates | 0 | Valid region-specific CloudFormation schemas. The AWS change sets also passed service validation. |
| `node frontend/tests/remote-agent.mjs <restricted fixture path>` | 0 on final loop | Hosted Cognito returned real access tokens. Missing and ID tokens received 401. AgentCore wrapped the runtime's wrong-workspace 403 and peer-owner 404 as HTTP 424. The owner received SSE, replayed the exact 13-event suffix across sessions, and cancelled an active run. |
| `python -m scripts.verify_agent_deployment` | 0 | Runtime and endpoint READY. Seven-day log retention, 60 s idle and 120 s lifetime. Inspected two live checkpoint objects using the existing project KMS key, private bucket configuration and 27 scoped IAM actions. |
| `python -m scripts.agent_identity_fixture disable` | 0 | Disabled three temporary validation users and removed their private local fixture. |

The remote SSE run recorded first event at **958.26 ms** and completion
at **28,610.92 ms**. It returned six cited claims from eight evidence IDs,
14 events including one terminal result, and two Nova Micro rounds at
514 and 643 ms. The observed fixture and frontend validation used 12
admitted HTTP attempts out of 20 allowed. The encrypted journal held two
completed reports and one cancelled run. The completed remote reports
recorded 1,521 input and 257 output tokens. Their estimated inference
cost is $0.000089215. The runtime ledger reserved $0.0005376 of its $0.05
allocation. Total observed local and remote inference was 4,056 input
and 660 output tokens, estimated at $0.000234360. The independent runtime
and supporting-service scenario remained below the authorized $5 allocation.
No AWS invoice total was used for these estimates.

Two OAuth verification attempts failed to reach a loopback callback.
A bound loopback receiver corrected the callback check. The next loop
identified AgentCore's HTTP 424 wrapper for application rejection, and
the final assertions verified both the wrapper and its inner 403/404.

Evidence is under `data/evidence/agentcore/` in `deploy-identity.log`,
`deploy-runtime.log`, `deploy-runtime-retry.log`, `runtime-smoke-4.log`,
`postdeploy-audit.log`, `usage-totals.log`, `cfn-lint.log`,
`regression.log` and `disable-fixture.log`. The deployed runtime is
`aegis_dev_investigations-…` in `us-east-1`, account ending 6271.
The verified deployed image digest is `sha256:6056e1cd…df12248`.
The existing G2 stacks and their guards were preserved. Standalone API
and static site hosting are outside the AgentCore deployment scope.

## 2026-11-24T05:17:50Z — G5 extension, mandatory local acceptance PASS

Reconciled prior gate commits `a63a46f`, `ff203dd`, `cbd82bf`,
`94eebd0`, and `15c4e94`. Contract review commit `7e191f1` precedes
geographic reads and the journey extension. The updated working copy of
IMPLEMENTATION_PLAN.md was preserved. Eight Iceberg tables and the selected
release `4e13ca6b-c2e1-4407-88bc-c362da7dbacb` remain intact.

| Command | Exit | Measured result and evidence |
| --- | ---: | --- |
| `python -m scripts.stage_network_context` with pinned archive and UTC capture time in source register | 0 twice | 14 immutable context rows. The CRTC Open Data catalog confirmed the archive and Open Government Licence. C-T5 supplies national and 13 regional LTE population rates for 2021. Ontario filters use the regulator row while retaining the country contour. `data/evidence/continuation/{crtc-metadata.json,stage-network.log}`. |
| `make lint typecheck test verify-phase1` | 0 each | 61 Python tests on the continuation working tree, real snapshot replay matched Parquet SHA-256 and sampled queries. `data/evidence/continuation/python-final-r2.log`. |
| `make smoke-local smoke-investigation smoke-agent-local` | 0 each | Seven REST baseline routes, six MCP tools, API and runtime journals, ordered SSE, replay and active cancellation. API 6.56 ms first event and 436.87 ms total, runtime loopback 5.81 ms and 428.44 ms. Shared release, deterministic mode, zero model calls. |
| `make lint-ui typecheck-ui build-ui` and `sh scripts/frontend.sh test` | 0 each | Strict type checking, Nuxt 4 production build and four frontend contract tests. Known Nuxt DevTools deprecation and bundle-size advisory remain. `ui-final-r2.log`, `ui-unit-final.log`. |
| `make smoke-ui-extension` | 0 | Three real Chromium cases in 26.5 s, authenticated production-mode Nuxt, worldwide and tactical visuals, Peru and Canada, separate layers, evidence detail, ordered SSE, no outbound help POST, responsive layout and zero uncaught browser errors. `data/evidence/continuation/browser-final-r2.log`. Screenshots under `data/evidence/g5-extension/` inspected for world, tactical, CVE detail, handoff, desktop and mobile. |

The first integration loop found that adding absent mitigation metadata
altered the established MCP payload. The second preserved the original
serialization. The first browser loop used the textarea text node
instead of its editable value. The corrected browser check verifies the
draft's contents and local editing.

Network context is enabled locally for the regulator series above.
OSIPTEL resource access returned HTTP 403. The other candidates and their
rights are recorded in `docs/source-register.md`. Conditional CVE
exposure is unavailable. Rendered positive geographic exposure, measured
zero, verified private site and SOC incident scenarios were not run.
There were zero CVE observations and no private site fields in the new
public-safe projection. All intelligence paths in this verification
required authenticated workspace access.

Next action is G6 local hosting validation and G7 evidence reconciliation.

## 2026-11-24T05:22:05Z — G6 hosting prepared locally, cloud acceptance BLOCKED

G5 extension commit `4d8c092`. The new CDK candidate prepares a private
versioned UI bucket and CloudFront OAC plus a regional streaming REST API
and ARM64 Lambda relay. The existing Cognito template can accept one exact
CloudFront callback and logout origin while preserving the existing client
ID, invite-only registration and OAuth Code flow. An AgentCore candidate
adds read scope only to the pinned CISA archive object needed for mitigation.
The deployed runtime and identity resources were preserved.

| Command or check | Exit | Outcome and evidence |
| --- | ---: | --- |
| `make synth-hosting synth-agent` and local `cdk diff --template ... --no-change-set` | 0 | Hosted, identity callback and AgentCore preparation. Hosting CDK assembly in `data/hosting-cdk/`. Offline diff was against an empty template. No AWS change set created. |
| `cfn-lint 1.60.1 --non-zero-exit-code error` with us-east-1 templates | 0 | Schema valid. W3005 remains for CDK's redundant explicit API role dependency. Synthesized invariants verified STREAM on both methods, streaming invocation URI, OAC signing, empty error TTL, logging, ARM64 and invite-only Cognito. `hosting-cfn-final.log`, `hosting-template-invariants.log`. |
| `docker build --platform linux/arm64 --provenance=false` and network-disabled container import | 0 | Container image built locally. API import and executable Lambda Web Adapter verified inside the ARM64 image. `hosting-image.log`. |
| `make build-ui-static` and `make smoke-ui-static` | 0 | Built with existing public Cognito metadata, workspace and callback HTML verified. Chromium checked actual static sign-in, S256 challenge initiation, invalid callback and no stored browser tokens in 2.2 s. External sign-in was intercepted. `ui-static-final.log`, `hosting-static-browser-r2.log` and inspected `static-login.png`. Initial check used the physical HTML path and reached the client router's 404; corrected to the callback route. |
| `pytest -s -q tests/integration/test_hosting_proxy.py` on the pinned release | 0 | Real two-hop local HTTP stream reached first SSE at 9.03 ms. Active cancellation through the relay, exact replay and workspace rejection passed. `hosting-loopback.log`. |
| AWS MCP read-only control-plane checks | Success | Exact STS account match ending 6271, us-east-1, configured prefix `aegis-dev`. Existing Cognito identity stack `CREATE_COMPLETE`. Existing scheduler `ENABLED`, `rate(6 hours)`. Existing Athena workgroup `ENABLED` with enforced 67,108,864-byte cutoff and SSE-KMS. No query or ingestion invoked. `aws-control-plane.json`. |
| `make hosting-preflight` | 2 (expected refusal) | Separate hosting authorization is absent. The guard stopped before STS or deployment. `hosting-approval.log`. |

Hosting estimate USD 0.27 for the stated bounded scenario, with lakehouse,
AgentCore and model charges accounted separately. See `docs/hosting.md`
for inputs, authorization, authenticated cloud smoke and rollback scope.
No new AWS writes, billable queries or model invocations were made.
The managed CloudFront/API Gateway/Lambda transport, callback update and
authenticated hosted smoke remain pending separately scoped approval.

## 2026-11-24T05:28:00Z — G7 available local evaluation PASS, final gate PENDING

G5 extension `4d8c092`. G6 local hosting preparation `3f8b7b8`. The
E01–E17 matrix in `docs/evaluation.md` separates current local checks,
previous live Bedrock and AgentCore evidence, conditional-source scenarios,
and the hosted gate. No additional model runs or paid Athena statements
were initiated. AWS MCP read-only checks confirmed the existing AgentCore
stack `CREATE_COMPLETE`, runtime and DEFAULT endpoint `READY`, JWT
authorizer configured, and lifecycle 60 s idle / 120 s maximum.
`data/evidence/continuation/runtime-control-plane.json`.

| Command | Exit | Actual result |
| --- | ---: | --- |
| `make lint typecheck test verify-phase1 smoke-local smoke-investigation smoke-agent-local` | 0 each | 63 Python tests and deterministic real snapshot replay. Added the mitigation source-instruction isolation check and the pinned Athena CISA guidance query check. Auth, parity renderer, API/MCP, replay and active cancellation verified. `regression-final.log`. |
| `make lint-ui typecheck-ui build-ui`, `sh scripts/frontend.sh test`, `sh scripts/frontend.sh audit` | 0 each | Strict build, four frontend contract tests and no known vulnerabilities reported by the registry audit. `ui-acceptance.log`, `ui-unit-acceptance.log`, `ui-audit.log`. |
| `make smoke-ui-extension` and `python -m scripts.verify_frontend_stream` | 0 each | Three Chromium cases in 34.7 s. The Canada-scoped CVE remained accessible from the active filter, with scope preserved through SSE and the editable handoff. The compiled SSE client read 10 events, 18.64 ms first event and 804.19 ms to completion. `browser-acceptance.log`, `stream-client.log`. |
| `make build-ui-static smoke-ui-static` | 0 each | Latest static artifact compiled with the verified public OIDC configuration. One real Chromium check passed in 2.7 s. `static-acceptance.log`. |
| `make eval-g7` | 0 | Seven scenarios. 22 supported of 22 factual claims, 100% grounding. Two correct claim-free responses are outside this denominator. Zero fabricated observations and no private disclosure observed in exercised paths. No billable inference, so no tokens consumed. `grounding-acceptance.json`, `timing-acceptance.log`. |
| `python -m scripts.verify_g3_athena --extension` | 1 (expected refusal) | The extension could not confirm remaining Lakehouse allowance. The guard prevented execution. `athena-extension-guard.log`. Prior same-release Athena evidence remains six cases, seven queries and 10,210,468 scanned bytes. |

The real local assessment used CISA capture content, dated FIRST EPSS
values and pinned NVD metrics and checksums. First event 4.96–7.23 ms and
completion 109.27–446.22 ms over seven cases. Mitigation completion
291.43–325.46 ms over four cases. Median component spans were 23.20 ms
for 32 DuckDB reads, 36.33 ms for 37 MCP calls and 1.62 ms for 68 SQLite
checkpoint updates. Previous live Bedrock and runtime timing/token figures
are retained with their original dates and environments. Cold starts and
new remote per-component latency remain unmeasured.

Next action is to reconcile remaining G2 and inference allowances and
obtain separate authorization for the hosted UI, cloud API, exact
Cognito callback and scoped AgentCore revision. Then run new Athena detail
parity, live mitigation inference and authenticated hosted end-to-end SSE.
Conditional aggregate exposure and optional private site and SOC incident
positive tests remain unavailable. The updated IMPLEMENTATION_PLAN.md
remains the user's original working-tree edit with its acceptance criteria
intact. The root .env remains ignored at mode 600.

## 2026-11-24T07:11:00Z — Final deployment resumed and live evaluation extended

Resumed `7e191f1`, `4d8c092`, `3f8b7b8` and `7176651`. G1–G5
remain closed. The identity and hosting implementation is commit `690555e`.
The user's implementation plan remains a working-tree edit. The separately
authorized G6 USD 5 ceiling was persisted in the ignored mode-600 `.env`
alongside the existing USD 15 Lakehouse, USD 5 Bedrock and USD 5 AgentCore
scopes. No credential was changed.

| Command or operation | Exit | Evidence and outcome |
| --- | --- | --- |
| `make hosting-preflight` | 0 | Exact STS account ending 6271, profile `default`, `us-east-1`, prefix `aegis-dev`. AWS MCP verified ownership tags on Lakehouse, bootstrap, Cognito and AgentCore. Scheduler stayed enabled at six hours. Athena retained its encrypted enforced workgroup and 64 MiB scan cutoff. |
| `make lint typecheck test` | 0 | 65 tests, including signed-token lifecycle, stale-session refusal, MFA and admin guard. `data/evidence/final/final-python.log`. |
| `make lint-ui typecheck-ui` | 0 | Nuxt lint and strict typecheck. Existing Nuxt DevTools warning. `data/evidence/final/{final-code-checks,hosted-contract-checks}.log`. |
| `make synth-hosting synth-agent`, pinned `cdk diff --no-change-set`, `cfn-lint` | 0 | Live differences reviewed for each stack. cfn-lint reported redundant role-dependency warnings. Evidence in `data/evidence/final/`. |
| `python -m infra.agent_deploy identity --review-only --enable-google` | 0 | CloudFormation reports `Replacement: False` for the existing Pool and Browser client. The creation review for hosting and runtime update review also passed. `data/evidence/final/{identity,runtime,hosting}-review.log`. |
| `python -m scripts.verify_g3_athena --extension --confirmed-remaining-usd 5` | 0 | One live detail case on the pinned release, eight queries, 5,488,587 bytes. `data/evidence/final/athena-detail.log`. |
| `make eval-g7` | 0 | 22/22 deterministic factual claims grounded, two correct claim-free cases, zero model calls. `data/evidence/final/grounding-local.json`. |
| `python -m scripts.evaluate_release --bedrock` | 0 | Two local HTTP investigations with live Nova Micro. 7/7 facts supported, 444 input and 100 output tokens, estimated USD 0.00002954. First events 7.95/8.61 ms, total 1,059.22/730.10 ms, model 795/466 ms. `data/evidence/final/grounding-bedrock.json`. |
| `python -m infra.agent_deploy runtime` | 0 on retry | Existing runtime revision 2 READY, seven-day logs, immutable ARM64 image digest `sha256:28e47039…149a82`. `data/evidence/final/runtime-deploy-r2.log`. |
| `python -m infra.hosting_deploy google-mapping` | 0 | Existing Google provider retained. Scoped email and email verification mappings reconciled without logging or overwriting credentials. Google sign-in acceptance requires a successful federated login. |

Pre-rollout inference ledgers reserved USD 0.0008960 locally and
0.0005376 in AgentCore against their existing USD 0.05 allocations. Account
Cost Explorer gross usage by relevant services (before credits) was taken
as a conservative bound since the Project cost-allocation tag is inactive.
The Lakehouse subset was USD 4.0433290793, Bedrock USD 0.12495946, AgentCore
USD 0.155146868, and API Gateway USD 0.000643. These are account-level
service totals and may include unrelated workloads. The relevant services
were net USD 0 or credit rounding at the time of the query. After the
forward Lakehouse operating and hosted-pilot reservations, USD 4.96967
remained in the conservative model. The runtime retained USD 4.24485 after
its USD 0.60 reservation. A USD 1 hosting reservation covers the USD 0.27
bounded monthly estimate and rollout/identity traffic. Actual
project-attributable billed spend remains unavailable. See
`data/evidence/final/cost-scope.txt`.

The first Docker invocation stalled while resolving public registry
credentials. A separate buildx builder timed out at 58 seconds. The retry
used a temporary Docker config to avoid the desktop credential helper and
published only to the owned ECR repository. The first hosting invocation
stopped at the empty, untagged CloudFormation review placeholder. Verified
zero resources and change sets, then retried creation in the owned account.
The hosting change set subsequently created the API stage and CloudFront
resources. G6 and final G7 acceptance are pending hosted verification.

## 2026-11-24T07:28:00Z — Hosting deployed and managed investigation verified

Assigned workspace [https://d13u8qrh8t434t.cloudfront.net](https://d13u8qrh8t434t.cloudfront.net).
CloudFront `E1K9JTWAXO2IQS` reports Deployed, origin access control and a
60-second API origin response timeout. The UI bucket blocks all public
access. The regional REST API `3tias9rsre` uses the verified streaming
integration with a 65-second limit. Hosting, identity and AgentCore stacks
are `UPDATE_COMPLETE`. The Cognito physical pool and browser client are
the original IDs. Rechecked exact hosted and loopback callbacks, OAuth Code
flow, the native and Google providers, and token revocation. The runtime is
revision 2. The pinned release and verified Canadian companion remain in
the existing lake. No domain was purchased and no DNS records changed.

| Command or observation | Exit | Evidence |
| --- | --- | --- |
| `python -m infra.hosting_deploy deploy` | 0 on corrected rollout | Stack created after verifying the empty preview placeholder. API readiness initially timed out. In-place update enabled async Web Adapter initialization, deferred cloud reader initialization, and allocated 1.5 GiB. The reviewed 60-second CloudFront origin update completed. `hosting-deploy-r2.log`, `hosting-readiness-deploy.log`, `edge-timeout-deploy.log`. |
| `python -m infra.agent_deploy identity --hosted-origin <assigned-origin> --enable-google` | 0 | Existing pool and app client updated in place. Cognito registered native/Google entry points and kept exact OAuth allowlists. `identity-deploy.log`. |
| `python -m scripts.platform_admin invite` | 0 twice | Cognito issued the administrator invitation to the private mailbox the first time. The repeat only assigned the already present group and did not send a new invitation or set a password. Permanent user remains enabled in `FORCE_CHANGE_PASSWORD` awaiting verified mailbox and TOTP enrollment. |
| `make deploy-ui` | 0 | Latest static app published 85 files. The asset scan found no source maps, AWS credential markers, private-key markers or local backend configuration in the served bundle. `native-ui-publish.log`. |
| Direct endpoint and CloudFront probes | 0 | Both returned 401 without a bearer. Unapproved-origin preflights returned 403 and no CORS allow header. `direct-and-edge-auth.log`. |
| `make smoke-cloud` | Partial, exit 2 | Hosted HTTPS, PKCE, pending view, no browser-stored access or refresh tokens, unauthorized admin and protected direct API and AgentCore denial case passed. The approved journey hit an incorrect drawer selector before starting an investigation. `production-smoke.log`. |
| `python -m scripts.smoke_cloud --journey-only` | Partial, exit 1 | Corrected graph-to-card journey ran live. Nine ordered SSE events and one completed terminal event. Owner replay returned the exact suffix. Peer replay yielded a wrapped 409 for an absent cursor in the peer namespace. The assertion expected 404 and was corrected once the branch was confirmed. `production-journey-r2.log`, `production-mitigation.json`. |
| `python -m scripts.evaluate_release --hosted-evidence data/evidence/final/production-mitigation.json` | 0 | 4/4 hosted factual claims supported. First response headers 2,029.22 ms, visible progress 2,996.45 ms, report 16,216.16 ms, model 448 ms. 222 input and 59 output tokens. Estimated model cost USD 0.00001603. `grounding-hosted.json`. |
| `python -m scripts.smoke_cloud --session-only` | 0 | Passed in 40.1 s. Explicit cancellation returned 200 and one cancelled terminal event. Direct peer cancellation was denied. Browser logout invalidated the previous token. `production-session.log`, `production-session-checks.json`. |
| Browser native and Google checks | Partial | Real native sign-up succeeded and Cognito's email arrived in the controlled mailbox. That connector withheld the one-time code. The temporary signup was disabled. The public attempt to register the reserved administrator was rejected by the Cognito trigger. Browser recovery showed the real Cognito form. Google reached its real sign-in page. No completed federated user or password recovery was observed. |

One Lambda cold report recorded 9,817.23 ms initialization plus
30,199.66 ms invoke time. Two warm anonymous authorization calls took
2.24 and 1.89 ms within Lambda. End-to-end anonymous probes were 669 ms
through CloudFront and 309 ms through direct API. Hosted mitigation used a
different authenticated execution path. The revised illustrative monthly
hosting estimate is USD 0.30 within the USD 1 rollout reservation and
USD 5 hosting scope. Cost Explorer cannot attribute actual billed spend
to this project. The modelled and observed usage amounts above are
separate from invoice totals.

The browser validation sets were disabled. The permanent administrator
remains enabled and awaits private onboarding. Production captures show
sign-in, registration, a redacted pending account, the command center, the
CVE card and investigation progress in `data/evidence/final/`.
Canada returned network context, Peru returned unavailable network context,
and CVE geographic exposure was empty in both. Private confirmed sites
and SOC incidents remain disabled.

**G6 and G7 remain BLOCKED on owner-side identity acceptance.** Complete
private administrator onboarding, actual approval/rejection/suspension
from `/admin`, the native verification and recovery challenges, and
Google sign-in with a controlled temporary Google identity. The dashboard,
identity controls, managed SSE, verified Bedrock evidence and deployed
services are available for those checks. Approval notifications remain
disabled because SES has sandbox access with zero verified identities.

## 2026-11-24T07:29:45Z — Temporary identity and cost reconciliation

The deployed readiness and native signup corrections are in `a0b6e40`.
`python -m scripts.verify_identity_challenge` passed on its second attempt.
Cognito required `NEW_PASSWORD_REQUIRED` for a disposable account, confirmed
the changed password, enrolled TOTP and required `SOFTWARE_TOKEN_MFA` on
the next authentication. The first attempt reused the enrollment code and
Cognito returned `ExpiredCodeException`. The corrected test waited for the
next authenticator interval. Both disposable identities were disabled.
Evidence is in `data/evidence/final/identity-challenges{,-r2}.log`.
The permanent administrator still needs its own mailbox verification,
password change and authenticator enrollment.

Final inference ledger reservations were USD 0.0012544 locally and
USD 0.0007168 in AgentCore. Each allocation remains USD 0.05. The final
Python regression returned exit 0 with 65 tests, and lint, typecheck and
the Nuxt static build passed. Safe CloudFront and direct denial checks and
the authenticated cancellation run used the real cloud service. The
original browser journey wrapper exited nonzero on its peer assertion.
The direct peer cancellation and logout checks passed independently.
G6 and G7 remain open on the owner-side identity cases listed above.

## 2026-11-24T07:51:00Z — Permanent administrator onboarding recovery

Read-only STS and owned-stack checks confirmed account ending 6271 and the
original Cognito pool. An exact email lookup and a full pool enumeration
found one matching identity, the enabled native `aegis-platform-admin`.
The account was `CONFIRMED` and in `aegis-dev-admins`, with email
verification and preferred TOTP still missing. The application decision
for the same subject was `PENDING_APPROVAL`. It contained one revoked
browser session, zero decision audit entries, and a zero approval cutoff.
There was no separate Google profile to link.

A sign-out during onboarding wrote the default pending decision to preserve
session revocation. The previous onboarding command rejected every
preexisting decision except `APPROVED`, so it aborted before proving email
ownership or enrolling TOTP. The owner reproduced this behavior with
`DataError: administrator account has an unexpected existing decision`.
After the correction, onboarding accepted the current password and
reached Cognito email verification. The owner's first verification attempt
returned `CodeMismatchException`.

The corrected operator command resumes a pending record that has no
decision history or revocation cutoff. It preserves closed sessions and
uses a conditional write after verifying the same native subject, mailbox
ownership, enabled preferred TOTP and completed Cognito confirmation. It
continues to guard against replacing a substantive decision. Cognito
verification permits up to three attempts. A mismatch retains the same
challenge and an expired code triggers a fresh email. The hosted UI now
shows **Administrator setup required** for the incomplete reserved account.
Regular approval and JWT authorization checks use the existing API/runtime
code. The pool, password, group and provider links were not changed by this
repair.

`make lint typecheck test` passed with 71 tests.
`make lint-ui typecheck-ui` and `make deploy-ui` passed. A read of the
actual CloudFront bundle returned HTTP 200 and contained the new setup
guidance. Logs are in `data/evidence/admin-recovery/`. Permanent hosted
administrator authorization is pending the owner's private verification and
fresh Cognito sign-in.

The public Chromium smoke passed one hosted HTTPS and unauthorized-access
case in 10.9 seconds. Cognito confirmed the owner's email verification at
2026-11-24T07:49:45Z. TOTP enrollment and application activation remained
pending at the next read.

### Authenticator challenge follow-up

Cognito CloudTrail recorded successful email verification and TOTP key
association, followed by `VerifySoftwareToken` returning
`EnableSoftwareTokenMFAException` with `Code mismatch` at 07:50:47 UTC.
The command now offers three verification attempts against the same TOTP
enrollment key and only applies the preferred factor after Cognito reports
success. The final authorization regression passed all 72 tests
(`data/evidence/admin-recovery/authorization-totp.log`). At 07:54:39 UTC
Cognito still showed verified email and no enrolled or preferred factor.
No application approval was written by the operator outside the private
onboarding flow.

## 2026-11-24T08:02:19Z — Scannable administrator enrollment

The private onboarding command now displays a QR code before prompting for
the authenticator's six-digit code. The macOS renderer receives the setup
URI over stdin and displays the QR and manual fallback only on the owner's
terminal. Apple Vision recovered the exact dummy URI from the rendered
matrix. `make lint typecheck test` passed with 72 tests. This update affects
the local onboarding command. The owner's phone pairing remains a private
step.

## 2026-11-24T08:18:18Z — Single authenticator attempt

CloudTrail showed that each of the owner's previous three submissions had
received `Code mismatch` in the enrollment verification operation. They
were retries of one challenge, with no MFA factor enrolled. The Mac clock
was within 0.08 seconds of the Cognito HTTP response date. The onboarding
operator command now displays a QR with a unique setup ID, prompts exactly
once, and compares the entered code to that key locally. A match results
in a single Cognito verification request with SDK retries disabled. The
disposable-account smoke verified a locally matched enrollment and a
subsequent real TOTP challenge, then disabled the test account. The final
lint, typecheck and all 73 tests passed. The permanent profile was not
modified by the validation.

## 2026-11-24T10:58:34Z — Permanent administrator and combined production smoke verified

The owner signed in as the permanent native `aegis-platform-admin` account
(`admin@oscarbahamonde.com`) and opened the hosted workspace and
`/admin`. The owner observed 17 directory entries, ten pending approvals,
seven approved decisions and zero suspended decisions. An independent
inspection of the authenticated Chrome session confirmed those values and
opened the protected audit. A read of the live Cognito and decision records
confirmed an enabled native subject, verified email, current administrator
group, enabled preferred software TOTP, and an APPROVED decision. The
activation audit records that same actor and target, `activate_admin`,
`2026-11-24T08:22:43.538609Z`, and outcome `applied`. The permanent row
exposed the audit action only. The live verification made no change to the
permanent account, its password, group or MFA. Its positive authorization
and onboarding are verified. The ordinary-user lifecycle still requires
authenticated administrative decisions.

| Command or observation | Exit | Evidence under `data/evidence/production-acceptance/` |
| --- | --- | --- |
| Owned-stack and live directory read | 0 | `control-plane.json`. Before new tests, Cognito had 16 disabled directory entries alongside the permanent administrator. The old dashboard included disabled identities in its application decision counts. Live directory status was verified, and the complete historical creation-to-disable join is pending. |
| First combined smoke via `scripts.smoke_cloud` | 1 | `full-smoke.log`. Pending denial and cancellation/logout passed. The journey waited on an evidence request even though the CVE detail already supplied that record to the browser cache. The wrapper timed out and its cleanup STS call reported `ExpiredToken`. |
| Corrected combined Chromium smoke, using the same scoped fixture and CloudFront URL | 0 | `full-smoke-r2.log`, three passed in 2.3 minutes. The CVE evidence ID rendered in the browser, the authenticated evidence endpoint returned the pinned snapshot, and the endpoint refused anonymous access. The run covered ordinary administrative denial, world/Canada/Peru, relationships, live mitigation, owner replay, peer denial, editable handoff, cancellation and logout. |
| `python -m scripts.evaluate_release --hosted-evidence <production-mitigation.json>` | 0 | `grounding-hosted.json`, four of four factual claims supported. The report completed in 27.39 s with visible progress at 15.39 s and headers at 14.57 s. Nova Micro took 534 ms and used 222 input and 59 output tokens, estimated USD 0.00001603. Nine ordered mitigation events and one terminal event. The browser run did not isolate cold and warm timings. |
| Combined cancellation and logout evidence | 0 | `production-session-checks.json`. Explicit cancel returned 200 and emitted one cancelled terminal event. Peer cancellation was denied and logout revoked access with the previous token. |
| Genuine expired-token API check | HTTP 401 | `expired-token-check.json`. The API denied the original fixture token after its signed expiration. |
| Live static bundle scan | 0 | `bundle-inspection.json`. Three HTML documents, 36 assets and 6,044,554 bytes. Zero access-key, private-key, source-map or loopback API markers. Tested sessions stored no access or refresh token persistently. |
| `make lint typecheck test`, `make lint-ui typecheck-ui`, `sh scripts/frontend.sh test` and `make build-ui-static` | 0 | `python-regression.log`, `ui-checks-final.log`, `frontend-contracts.log`, `static-build.log`. 73 Python tests and four frontend contracts passed. The locally built dashboard distinguishes Cognito-disabled entries from active decisions and retains their audit. Publication of that change is pending. |
| Native public signup in Chromium | HTTP 200 | Cognito accepted a dedicated validation registration and displayed email verification. The private creation receipt records the exact alias and request identifier. Confirmation and password recovery need private mailbox interaction. |

The live CloudFront application used the existing API Gateway, AgentCore and
pinned Iceberg release `4e13ca6b-c2e1-4407-88bc-c362da7dbacb`. Canada
continues to report historical CRTC LTE population coverage. Peru had no
network context, and neither scope emitted CVE geography. Private confirmed
sites and SOC incidents remain disabled. The archived parity observation
of eight Athena queries and 5,488,587 bytes remains the current measured
detail-query baseline. The browser rerun did not measure new scanned bytes.
Production captures include sign-in, the redacted pending state, the world
map beside the relationships, CVE detail and the live report. A separate
hosted check verified the rendered globe canvas. It made no model call.

The approved ceilings remain USD 15 lakehouse, USD 5 Bedrock, USD 5
AgentCore, and USD 5 hosting/identity. Before the new run, the local and
runtime inference ledgers reserved USD 0.0012544 and USD 0.0007168 of their
separate USD 0.05 allocations. The reconciled remaining pilot estimates
were USD 4.97 lakehouse, USD 4.78 Bedrock, USD 4.24 AgentCore and USD 4.00
hosting before this run. Cost Explorer reported service-level account
estimates, including USD 0.12495946 Bedrock, USD 0.155146868 AgentCore and
USD 0.000643 API Gateway for the observed month. Project allocation was
unavailable, so those amounts are not attributed project charges.

**G6 and G7 remain BLOCKED on the mandatory identity acceptance and
cleanup.** Hosted admin approval, rejection, suspension and restoration,
native confirmation and recovery, and completed Google authentication
remain open. The scoped AWS operator session expired during the first
smoke. A read-only retry returned `LoginRefreshRequired`
(`operator-session-recheck.log`). The three temporary smoke identities'
exact subjects and creation
receipts are retained in the private manifest for confirmed disablement.
The separate public-signup validation identity also needs cleanup after
mailbox work. Await private owner participation for the browser challenges
and AWS session renewal. G1–G5 remain closed.

Verified source increments were `a642ab2` for the combined browser harness
and fixture receipts, `8bdfd1e` for the locally built administrator view,
and `5358871` for globe-rendering readiness.

## 2026-11-24T11:51:52Z — V2 local official vulnerability corpus verified

The data audit recovered the pinned MVP and its verified production
evidence at `e17565d`. The V2 capture uses separate local artifacts under
`data/v2/vulnerabilities/`. The [V2 roadmap](ROADMAP_V2.md) and
[ingestion runbook](docs/v2-ingestion.md) describe the milestones and
source denominators.

| Command or observation | Exit | Evidence under `data/evidence/v2/` |
| --- | --- | --- |
| `python -m pipelines.bulk_vulnerabilities kev nvd cve` | 0 after correction | `official-vulnerability-bulk-r2.log` and `vulnerability-baseline.json`. All 25 NVD annual feeds and the modified feed, the complete KEV catalog, and the CVE Program baseline and delta passed the source-count checks. |
| `python -m pipelines.bulk_vulnerabilities kev nvd cve --sync-nvd` | 0 | `vulnerability-sync.log`. Existing captures and the NVD index reproduced the original match and completeness counts. |
| `python -m pipelines.kev_history` | 0 after correction | `kev-history-r2.log` and `data/v2/kev-history/history.json`. 347 of 348 available Git revisions validated. One malformed upstream JSON revision was retained and recorded as a gap. |
| Repeated official KEV history capture | 0 | `kev-history-replay.log`. The same Git head and checksum-verified segments reproduced all totals. |
| `make lint typecheck test` | 0 | `regression-final.log`. 80 tests passed, including the pinned MVP regressions and V2 archive cases. |

The first corpus attempt downloaded the correct CVE release asset but
found zero CVE members in its outer ZIP. The corrected parser verified
and streamed the nested ZIP from a bounded temporary file. It kept NVD
and CVE Program payloads independently, including descriptions, status,
all source metrics, references, applicability expressions and CNA/ADP
containers. The CVE Program baseline and delta had 431,604 file records
and 431,119 distinct CVEs. NVD had 440,131 file records and 431,114
distinct CVEs. KEV matched both sources on 1,792 of 1,792 CVEs.
No records were rejected or duplicated within the current artifacts.
The corrected bulk run took 52.02 seconds with a peak RSS of 522,403,840
bytes. The original archive retrieval took 399.93 seconds before it
encountered the ZIP wrapper. Incremental verification took 33.56 seconds.
V2 AWS writes and model calls totalled zero.

## 2026-11-24T11:53:56Z — EPSS archive index and bounded historical ingestion verified

The latest official EPSS file for 2026-11-23 produced 411,399 valid
records. The official archive tree had 2,041 available files from
2021-04-14 through 2026-11-23, with nine calendar dates absent. Its
compressed payload denominator was 2,812,440,549 bytes. The date-grain
runner ingested 43 available days, 6,477,173 score rows, and zero rejected
or duplicate rows. It preserved null percentiles for 1,637,480 older v1
records. The deduplicated date pointers and source receipts support
bounded resume. The first 30 calendar dates yielded 25 of 25 listed
files. Subsequent samples spanned six calendar years and the live trend
check preserved the June 2026 model transition.

The first historical runs encountered a provider v1 file with two
columns and an HTTP 403 on a date absent from the official archive.
The corrected runner preserves optional percentile and uses the official
archive manifest with an explicit absent-date result. The final seven
sample ranges and the model-boundary trend returned exit 0. Evidence is
under `data/evidence/v2/epss-*.log` and
`data/evidence/v2/epss-methodology-trend.json`.

Raw and normalized samples total 94,573,185 bytes. The measured
year-specific size ratios project 7.20 GB for the full EPSS archive
and Parquet. Available disk was 2.93 GB before the 1 GiB reserve.
Complete EPSS normalization is blocked by local storage. The runbook
records an approximately 8 GiB free destination for EPSS and bounded
cloud cost scenarios. Continue V2.2 source qualification independently.

## 2026-11-24T12:04:17Z — Local global network context and capability audit verified

| Command or observation | Exit | Evidence under `data/evidence/v2/` |
| --- | --- | --- |
| `python -m pipelines.wdi_context` and checksum-verified rerun | 0 | `wdi-context.log` and `wdi-context-replay.log`. Two official World Bank API manifests yielded a versioned dimension of 217 economies and 14,322 yearly ITU subscription records. 214 economies have measured values in the archive and 151 in 2024. |
| `python -m pipelines.network_registry` | 0 after correction | `rir-context-r3.log`. The NRO source SHA-256, 776,338 total rows and 117,801 ASN rows matched their headers. The projection kept only 363 coarse registration aggregates, covering 240 published country codes and five RIRs. |
| DuckDB read of both network outputs | 0 | `network-parquet-check.json`. WDI has zero country dimension orphans. Its 3,728 nulls and 4,058 explicit zero readings stayed distinct. The RIR schema includes no individual network identifiers. |
| Existing Shodan account and field metadata | HTTP 200 | `shodan-capability.json`. Plan label `oss`, zero query and scan credits, 94 filters and 90 facets. The verified account metadata does not establish aggregate observation entitlement or public reuse. The collection has no CVE aggregate evidence for the 431,119 staged CVE Program IDs. |
| DuckDB CVE-source overlap benchmark | 0 | `duckdb-corpus-timings.json`. 431,100 joined IDs, 549.05 ms first query and 381.92 ms repeat on one connection. OS cache was uncontrolled. |
| `make lint typecheck test` and frontend contracts | 0 | `regression-release.log` and `frontend-contracts.log`. 84 Python tests and four frontend tests passed. |
| Existing CloudFront HTTPS root | HTTP 200 | `production-https-head.log`. Previous G1–G7 evidence remains pinned. |

The first NRO stream closed after a partial transfer. The corrected
client used bounded ranges with an ETag and verified the official
payload checksum. The first ranged parse rejected the unterminated
last line. The subsequent parse consumed it and reconciled all counts
in 57.62 seconds with 148,029,440 bytes maximum RSS. Network statistics
remain local pending the V2 release. CVE geographic exposure
and inferred network associations still require qualified source evidence.
The full EPSS history needs a larger volume. Expanded Iceberg publication
and hosted acceptance require separately scoped cloud authorization.
