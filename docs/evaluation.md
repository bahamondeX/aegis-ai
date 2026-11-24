# G7 acceptance matrix

Evaluate the pinned capture `4e13ca6b-c2e1-4407-88bc-c362da7dbacb`.
Run `make lint typecheck test verify-phase1 smoke-local smoke-investigation
smoke-agent-local`, then run `make lint-ui typecheck-ui build-ui`,
`sh scripts/frontend.sh test`, `make smoke-ui-extension` and `make eval-g7`.
Use the [source staging steps](source-register.md) for the independent
Canadian context evidence. `STATUS.md` has timestamps and command exits.

| Case | Local outcome and evidence | Additional acceptance |
| --- | --- | --- |
| E01 Stable ranking | PASS. Real snapshot query, null ordering and tie-break tests in `test_live_snapshot.py` and `test_query.py`. | Prior same-release Athena queries verified. |
| E02 Relationship evidence | PASS. NVD CPE configuration and CWE path tests, authenticated MCP reads, browser graph and evidence drawer. | Prior Athena graph evidence verified. |
| E03 Unknown geography | PASS. Regional and Peru requests returned no regional rankings or observations. Missing coverage remained null. | Prior live Bedrock and runtime coverage behavior retained. |
| E04 Filters | PASS. Invalid country, region, dates, limit and mismatched mitigation CVE/release rejected. | `test_geography_policy.py`, authenticated REST/MCP smoke. |
| E05 Factual grounding | PASS. 22 of 22 factual claims across five claim-bearing local reports. Two correct claim-free reports reported separately. | Extended live Bedrock evaluation held pending budget reconciliation. |
| E06 Prompt injection | PASS. The model receives vetted claim keys and typed fact text. It can return only known keys. Tests reject unknown selections and malformed outputs. Archived text enters only the rendered, cited claim. | Unit tests use isolated SDK and model stubs. |
| E07 Timeout, throttle, budget | PASS for bounded local tests with stubbed provider failures. Existing live budget denial verified deterministic fallback and zero model calls. | No new provider throttle induced. |
| E08 Idempotency and replay | PASS. Exact suffix replay, conflicts and owner isolation on real snapshot across API, local runtime and relay. | Prior AgentCore replay retained as historical proof. |
| E09 Cancellation and SSE ordering | PASS. Active cancellation, disconnect handling, strict event IDs, one terminal event. | Hosted disconnect/timeout behavior needs cloud measurement. |
| E10 Auth | PASS. Expiry, issuer, token type, client, workspace and owner tests across the enabled local paths. | Prior Cognito and AgentCore remote tests retained. Hosted security checks pending. |
| E11 Athena parity | Prior PASS for six read shapes, seven queries, 10,210,468 bytes on the same release. Current extension builds the pinned detail query, checks local real replay and exercises the new read in DuckDB. | BLOCKED for new live CVE-detail parity until verified remaining G2 allowance is available. |
| E12 UI state | PASS. Typed SSE filter proposal, atomic application, stale event and manual override tests. Chromium verified the proposal and subsequent manual country filters. | Local application only. |
| E13 Worldwide and country filters | PASS. Chromium saw real world contours, a nonblank tactical map, Peru and Canada via one country selector and desktop/mobile layouts. | `world-layers.png`, `tactical.png`, `mobile.png`. |
| E14 Independent network context | PASS. Canada regulator coverage and Ontario drill-down remained separate from CVE filters and exposure availability. Peru showed uncovered network context. | Positive data verified only for the qualified Canadian series. |
| E15 Estimated vs verified locations | PASS for no-fabrication and disclosure checks. Public projection emits no observations or private fields. | Positive aggregate, verified-site and optional private incident scenarios NOT RUN. No qualified authorized observations available. |
| E16 Coverage and category semantics | PASS for unavailable/null versus measured-zero policy and explicit categories. Chromium saw independent legends and no estimated or private features. | Positive real measured-zero, sensor and incident cases NOT RUN. |
| E17 Mitigation and privacy | PASS locally. Graph → exact CVE card → authenticated four-node SSE → editable handoff, with the same release, exact CVE and Canada scope. No outbound action was observed. Unknown scope and applicability remained explicit. | Hosted verification and Nova Micro on the extended request pending. |

## Grounding and measured latency

`make eval-g7` compares every emitted claim and cited checksum with the
captured CISA KEV entry, dated FIRST EPSS row or pinned NVD source record,
including the exact CISA required-action text. It counts unsupported claims
against the denominator. Its four mitigation reports contributed 14 claims.
The global ranking contributed eight. The two correct no-data reports are
outside the claim denominator. The deterministic local evaluation did not
invoke a model or generate geographic observations.

| Measurement | Observed result | Boundary |
| --- | ---: | --- |
| First SSE event | 4.96–7.23 ms | Seven loopback cases |
| Full investigation | 109.27–446.22 ms | Seven loopback cases |
| Mitigation full investigation | 291.43–325.46 ms | Four loopback cases |
| DuckDB read spans | 32, median 23.20 ms, max 52.63 ms | SQL reads; nested in MCP |
| MCP tool spans | 37, median 36.33 ms, max 151.70 ms | Local authenticated MCP calls |
| Checkpoint update spans | 68, median 1.62 ms, max 3.32 ms | Local SQLite updates |
| Hosted-design relay test | 9.03 ms to first event | Local TCP proxy → runtime HTTP; synthetic transport boundary only |

Nested tool and query times can overlap. The suite did not measure cold starts.
Artifacts are `data/evidence/continuation/grounding-acceptance.json`,
`timing-acceptance.log`, `hosting-loopback.log` and the screenshots in
`data/evidence/g5-extension/`.

## Reused live evidence and remaining cloud checks

- G4 Nova Micro Converse at `cbd82bf` measured 507 input and 73 output
  tokens in the cancellation-loop report, 1,012 ms invocation-path latency,
  13.38 ms to first SSE event and 1,728.73 ms total. Its estimated inference
  cost was USD 0.000027965. This is historical baseline evidence.
- The G4 real budget denial had no inference usage. The baseline produced
  eight cited fallback claims and completed in 877.20 ms.
- The G6 AgentCore baseline at `15c4e94` measured 958.26 ms to first event
  and 28,610.92 ms to completion in the logged run. The earlier Athena
  query log distinguishes provider query times. These logs cannot isolate
  remote runtime, startup or checkpoint overhead from one another. The
  current relay and runtime instrumentation is available for a future
  authorized hosted smoke.
- The new CVE-detail parity command is
  `uv run --locked --no-sync python -m scripts.verify_g3_athena --extension
  --confirmed-remaining-usd <verified-G2-balance>`. It requires enough
  verified balance to cover at most 12 capped Athena queries, an upper scan
  estimate of USD 0.00402653184. The guard was tested without a balance.
- Final G7 remains pending until authenticated hosted UI/API/SSE verifies
  the release together. The deployed AgentCore and Cognito checks remain
  independently verified. The complete local path is reproducible without
  new model charges or managed infrastructure.
