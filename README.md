# AEGIS AI

AEGIS is an evidence-backed vulnerability intelligence workspace. It captures CISA KEV and
FIRST EPSS, enriches up to 20 KEV CVEs per run from NVD, and serves pinned releases through
DuckDB locally and Athena in AWS. The Nuxt 4 workspace combines source coverage,
relationships, geographic context and authenticated investigations.

## Quickstart

Use native Apple Silicon, Python 3.12 via uv, and the toolchain reported by `make preflight`.
Nuxt 4 uses the pinned Node and pnpm versions. The Python install uses `uv.lock`.
[Nuxt 4 requirements](https://nuxt.com/docs/4.x/getting-started/installation) ·
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

The V2 local ingestion command archives the complete pinned KEV, NVD and
CVE Program source corpora alongside the MVP release. See the
[V2 roadmap](ROADMAP_V2.md) and [bulk data runbook](docs/v2-ingestion.md).

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

## G3 local API

```sh
make bootstrap
make dev
```

The server listens on `127.0.0.1:8000`. `/health` identifies the selected
snapshot and `/docs` lists the REST schema. The command writes a 15-minute bearer
token to `data/local-api.token` at mode 600. Use it for the authenticated
`/v1/coverage`, `/v1/kpis`, `/v1/cves`, `/v1/map`, `/v1/graph`,
`/v1/evidence/{evidence_id}`, and Streamable HTTP MCP at `/mcp/`.

```sh
(printf 'Authorization: Bearer ' && cat data/local-api.token) |
  curl --noproxy '*' --header @- http://127.0.0.1:8000/v1/kpis
make test
make smoke-local
```

Both transports use the UUID selected from the root `.env` or the explicit
`SNAPSHOT` override. Ranked CVEs, country observations, and relationship edges
are constrained to the selected snapshot and typed filters. Date bounds apply
to KEV addition dates. Geographic responses explicitly report unavailable
coverage when the snapshot lacks observations for the cohort.

The G3 smoke starts an isolated loopback server and calls all six tools using
the official MCP client. The local JWT requires the loopback peer, audience,
issuer, expiry, and workspace. The application also supports an explicit
HTTPS JWKS verifier and Athena snapshot reader through its Python factory.
G3 verification runs over DuckDB. Cloud deployment and investigation streaming
are outside these local tests.
[MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk/tree/v1.x) ·
[FastAPI query validation](https://fastapi.tiangolo.com/tutorial/query-param-models/)

## G4 investigations

`make smoke-investigation` serves the real pinned DuckDB snapshot, calls the existing
MCP tools and verifies SSE, citations, filter proposals, replay and unavailable geography.
`make smoke-agent-local` exercises the AgentCore HTTP contract on loopback.
`make synth-agent` produces a separate local CloudFormation assembly under
`data/agentcore-cdk.out`.

An authenticated client POSTs to `/v1/investigations` with a bearer token and an
`Idempotency-Key`. The JSON body includes `question` and can specify `scope`
(`global` or `regional`), typed `filters`, and `snapshot_id`. Use a country
filter for a country-level investigation. Reuse the same key and body with
`Last-Event-ID` to replay outstanding events. To cancel, POST to
`/v1/investigations/{investigation_id}/cancel` with the same authenticated subject.
AgentCore receives the same request at `/invocations` and accepts
`{"action":"cancel","investigation_id":"…"}` there.

The graph builds and cites claims from retrieved evidence. With Bedrock enabled,
the model can select which existing claims to emphasize. The Validator builds
report text and visualization events from typed data. The frontend client
validates the SSE schema and applies accepted proposals and matching analytics
together. Manual filter edits take precedence over outstanding proposals.

Run the frontend contract checks with the Node and pnpm versions pinned at the
repository root. From the repository root, run `pnpm --dir frontend install
--frozen-lockfile`, `pnpm --dir frontend typecheck`, `pnpm --dir frontend test`
and `uv run --locked --no-sync python -m scripts.verify_frontend_stream`.
Regenerate the wire schema with `uv run --locked --no-sync python -m
scripts.export_investigation_schema`, followed by `pnpm --dir frontend contracts`.

The live Nova Micro gate passed under the scoped Bedrock approval. The
[G4 runbook](docs/g4-investigations.md) documents the approval and allocation
settings. The [status log](STATUS.md) records the measured latency, token
usage and independent budget fallback test.

## G5 command center

The dashboard runs on Nuxt 4.7, Nuxt UI 4 and Tailwind CSS 4 with strict
TypeScript. Node 22.22.3 and pnpm 10.32.1 are pinned. The operator interface
includes the geographic globe and tactical map, the CVE relationship canvas,
EPSS by rank, source coverage, evidence inspection, and a streamed
investigation workspace.

```sh
make frontend-install
make dev
```

In a second terminal, run `sh scripts/frontend.sh dev`, open
`http://localhost:3000`, and enter the development access token from
`data/local-api.token`. The Nuxt server proxies API requests to the
loopback API and forwards the operator token. It uses the same pinned
real snapshot for charts, filters and source provenance. Country contours
are from Natural Earth. The exposure layer only highlights countries with
evidence in the selected cohort.

For a production-mode local check, install Playwright Chromium with
`sh scripts/frontend.sh exec playwright install chromium --only-shell`,
then run the verification sequence.

```sh
make lint-ui typecheck-ui build-ui smoke-ui
sh scripts/frontend.sh test
```

The [G4 and AgentCore runbook](docs/g4-investigations.md) describes the
authorized Cognito and runtime configuration. [STATUS.md](STATUS.md) links
the observed browser check outputs and screenshots. Cloud hosting and a
standalone cloud API are separate deployment work.

## Geography and mitigation extension

The globe and tactical map open worldwide and offer separate network context
and CVE evidence layers. The pinned local companion includes historical
Canadian regulator coverage, with published provincial and territorial
values. Peru and other uncovered areas report unavailable. Current CVE
exposure is unavailable across the release. Measured zero requires a
qualified source and time window. Private site and SOC incident layers are
disabled. [Source register](docs/source-register.md) ·
[Data and API contracts](docs/geography-contract.md)

Open a CVE from the graph or ranked list to review version criteria, CVSS,
EPSS and source evidence. **How to mitigate** opens an authenticated
investigation on the selected release and scope. **Request help** opens an
editable SOC/CSIRT draft for operator review. It sends no messages or tickets.
An explicitly selected CVE stays accessible from its filter chip in areas
without geographic evidence.

```sh
make build-ui
make smoke-ui-extension
make eval-g7
```

Stage the optional regulator companion using the documented source command
before running the complete browser suite. The browser harness captures
actual production-mode UI under `data/evidence/g5-extension/`.
[World view](data/evidence/g5-extension/world-layers.png) ·
[Tactical map](data/evidence/g5-extension/tactical.png) ·
[Mitigation handoff](data/evidence/g5-extension/soc-handoff.png) ·
[Mobile view](data/evidence/g5-extension/mobile.png).
[Evaluation matrix](docs/evaluation.md) · [Execution evidence](STATUS.md)

## Hosted workspace and identity

[Open the AEGIS AI workspace](https://d13u8qrh8t434t.cloudfront.net).

The hosted design uses a private S3 origin behind CloudFront, a regional
streaming API and the existing AgentCore runtime. Native registrations and
Google identities require administrative approval. Verified accounts can
check their status while waiting. Administrators manage access and audit
history from `/admin`.

The owner verified access for the permanent native account
`aegis-platform-admin` at `admin@oscarbahamonde.com`. Use **Sign in** with
the native username, complete the authenticator challenge and open **User
administration**.

The [execution record](STATUS.md) lists the deployed resources and completed
acceptance checks. The [hosting runbook](docs/hosting.md) covers the scoped
rollout and teardown. The [identity runbook](docs/identity-management.md) covers
administrator onboarding and email operations.

The [technical case study](docs/case-study.md) and [demonstration script](docs/final-demo.md)
cover the deployed intelligence path. The [evaluation report](docs/evaluation.md)
records end-to-end evidence and the identity acceptance still pending.
