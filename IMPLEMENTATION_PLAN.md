# AEGIS AI — 48-hour implementation plan

Elapsed-hour targets, not a guarantee. Work sequentially through gates; parallelize independent read-only checks when useful. Start clock at actual execution. Record results in STATUS.md. Stop unauthorized cloud writes, not local development. Read AGENTS.md first.

| Window | Gate | Deliverable |
|---|---|---|
| H0–H5 | G1 | Real local ingestion, DuckDB, schema and evidence |
| H5–H11 | G2 | CDK, Iceberg, Athena parity |
| H11–H17 | G3 | FastAPI and typed MCP tools |
| H17–H23 | G4 | LangGraph and live Bedrock SSE |
| H23–H34 | G5 | Nuxt 4 command center |
| H34–H42 | G6 | AgentCore, hosting, cloud smoke |
| H42–H48 | G7 | Evaluation, polish, runbook and demo |

## G1 — Data first [FINISHED]
1. Inspect environment, initialize git if needed, uv project Python 3.12, install polars, pyarrow, duckdb, pyiceberg, httpx, pydantic, pytest, ruff, python-dotenv. Pin resolved versions. Scaffold directories, no CDK/Nuxt code.
2. Fetch CISA and current EPSS; validate schema, source date, checksum, provenance and nonempty records. Save raw and normalized Parquet. Fetch bounded NVD enrichment for up to 20 KEV CVEs, record missing/blocked items and cursor; fetch NVD without key using documented limits if needed. Store CVSS/CWE/CPE relationships and evidence references. Avoid full NVD download.
3. Probe optional Shodan aggregate capability with a generic non-vulnerability query and authorized account info; no secrets in output, no host enumeration. Record status only; ingest geographic exposure only from permitted aggregate or explicitly authorized inventory evidence. Else empty exposure table with coverage reason. Do not derive exposure from advisory URLs.
4. Build DuckDB views and shared SQL for KEV/EPSS ranking, coverage, product/CWE graph, geo aggregates. Test uniqueness, source links, date types, null handling, rerun idempotency. Publish manifest with cohort counts and source dates. Test actual query outputs.
5. Run `make verify-phase1` twice, checking same-snapshot counts and keys. PASS requires real CISA + EPSS, at least one real NVD enrichment with valid provenance, nonempty relationship query when supported, successful joins, valid no-data geography behavior. If NVD unreachable mark G1 BLOCKED; keep valid partial snapshots, do not substitute mocks or start CDK/Nuxt. Report actual row counts and next command.

## G2 — Lakehouse and infrastructure [FINISHED]
Build Python CDK after G1. Validate AWS CLI profile, region, STS account, permissions and explicit deployment authorization/cost ceiling. Create dedicated S3 buckets/prefixes, Glue database, Athena workgroup engine 3, KMS/SSM, roles, Scheduler and Lambda. Package native Python libraries for Lambda Linux ARM64, not macOS binaries; use compatible build image or wheel strategy. CDK synth/diff first. Bootstrap only if needed and authorized. Init Iceberg v2 tables via PyIceberg, verify metadata, publish local snapshot, invoke cloud ingestion via CLI. Compare local/Athena results for identical snapshot and cohort. Verify rerun no duplicated facts, encrypted storage, bounded queries and scheduler configuration. Gate: `make synth`, `make diff`, `make verify-cloud` green; if cloud authorization blocked, report and continue local backend only.

## G3 — API and MCP [FINISHED]
Implement typed adapters for DuckDB and Athena, parameter validation, query budgets, authentication and error mapping. Implement API endpoints and MCP tools defined in AGENTS.md; use real data and official SDK client to verify tool discovery/calls. Contract tests for invalid filters, missing evidence, no geography, stable ordering, auth isolation, limits and source freshness. Gate: `make test`, `make smoke-local` API mode; MCP integration actually calls DuckDB. Never expose raw SQL tool.

## G4 — Agentic workflow [FINISHED]

Live Bedrock verification passed with Nova Micro. Commit `cbd82bf` records the
verified G4 implementation and the [execution record](STATUS.md) captures
SSE latency, token use, citations and the separate fallback test.
Implement four-node graph, bounded retry, trace correlation and event schemas. Test real Bedrock model access and tool execution, then run investigation on real local snapshot. Test global and regional questions (region unknown must not imply exposure), empty inputs, timeouts, invalid filters, prompt injection in advisory text, evidence consistency and disconnect. Implement POST fetch SSE with heartbeat and final events; test streaming before completion. Gate: live Bedrock response grounded in actual evidence, valid filter event and terminal event; if model unavailable, show blocker, no simulated model output counted as pass.

## G5 — Frontend [IN-PROGRESS]
Install Nuxt 4, strict TS, compatible Nuxt UI/Tailwind and libraries. Build command center with lazy-loaded globe/map, graph, KPI/trends, CVE table, evidence and agent panel. Use real API coverage and snapshot information. Globe is valid with no exposure; clearly show unavailable geography. Use real geography outlines, no attack animations. Central typed filter store; SSE updates selected filters and data, manual selections update queries. Client-only WebGL, fallback, cleanup and responsive layout. Gate: pnpm lint/typecheck/build, Playwright actual browser tests with real backend, screenshots desktop/mobile, no fake data, agent changes UI state, no uncaught errors.

## G6 — Deployment [NOT-STARTED]
Package ARM64 AgentCore runtime using verified current deployment path. Deploy API with supported streaming transport; deploy static UI behind TLS with private S3/CloudFlare or authorized equivalent. Configure auth, CORS allowlist, runtime IAM, SSM secrets, log retention, rate limits and budgets. Verify AgentCore invocation from CLI and API, SSE arrival timing, cloud UI fetches, authentication and no public secrets. Verify scheduler configuration and manual ingestion invocation. Document every resource and teardown. Gate: `make smoke-cloud` with real authenticated browser/API, no local fallback masquerading as deployed backend. If deploy blocked, retain working local demo and state blocker.

## G7 — Evaluation and delivery [NOT-STARTED]
Use at least 12 evaluation cases derived from snapshot, including ranking, CWE/product graph, unknown geography, invalid filters, provenance, prompt injection, timeout, repeated request, stream disconnect, auth isolation, Athena parity, UI state. Report actual outcomes and latencies; target all critical safety/data tests green and >=95% grounding on factual claims with explicit denominator. No invented metrics. README quickstart, architecture diagram (Mermaid source), data dictionary, source/license notes, cost estimate, known limitations, actual screenshots, demo script, operational runbook and cleanup. Record exact commands and commit hashes. Run final lint/tests/build and cloud smoke if available.

## Scope reduction if time constrained
Keep real data, DuckDB/Athena, evidence, four-node graph, SSE, one working globe/map view, one relationship graph and KPI panel. Defer animation, tactical secondary view polish, durable cross-session recovery if not implemented (mark missing), advanced history/tenant features and optional sources. Never defer authentication for public deployment, data correctness, provenance or safety gates. Report each omitted mandatory item as incomplete, not success.

## Demo script
1. Open dashboard and show live source timestamps, coverage and KEV/EPSS ranking.
2. Ask: “Show the highest-priority known exploited vulnerabilities and explain the evidence.” Show tool events and synchronized graph/KPIs.
3. Ask: “What evidence is available for South America?” If no verified regional data, show unavailable layer and global context distinctly; never invent coordinates.
4. Open evidence drawer and verify source references. Show local/Athena parity and test output. Explain deployment limits and teardown.
