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
| E09 Cancellation and SSE ordering | PASS. Active cancellation, disconnect handling, strict event IDs, one terminal event. | Hosted explicit cancellation passed. Hosted disconnect and provider timeout behavior were outside the executed case. |
| E10 Auth | PASS. Expiry, issuer, token type, client, workspace and owner tests across the enabled local paths. | Prior Cognito and AgentCore remote tests retained. Hosted security checks pending. |
| E11 Athena parity | Prior PASS for six read shapes, seven queries, 10,210,468 bytes on the same release. Current extension builds the pinned detail query, checks local real replay and exercises the new read in DuckDB. | Final live CVE-detail parity passed after budget reconciliation. See the execution below. |
| E12 UI state | PASS. Typed SSE filter proposal, atomic application, stale event and manual override tests. Chromium verified the proposal and subsequent manual country filters. | Local application only. |
| E13 Worldwide and country filters | PASS. Chromium saw real world contours, a nonblank tactical map, Peru and Canada via one country selector and desktop/mobile layouts. | `world-layers.png`, `tactical.png`, `mobile.png`. |
| E14 Independent network context | PASS. Canada regulator coverage and Ontario drill-down remained separate from CVE filters and exposure availability. Peru showed uncovered network context. | Positive data verified only for the qualified Canadian series. |
| E15 Estimated vs verified locations | PASS for no-fabrication and disclosure checks. Public projection emits no observations or private fields. | Positive aggregate, verified-site and optional private incident scenarios NOT RUN. No qualified authorized observations available. |
| E16 Coverage and category semantics | PASS for unavailable/null versus measured-zero policy and explicit categories. Chromium saw independent legends and no estimated or private features. | Positive real measured-zero, sensor and incident cases NOT RUN. |
| E17 Mitigation and privacy | PASS locally. Graph → exact CVE card → authenticated four-node SSE → editable handoff, with the same release, exact CVE and Canada scope. No outbound action was observed. Unknown scope and applicability remained explicit. | Both live model and hosted mitigation passed. See the final deployment evidence. |

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

## Final deployment extension

| Case | Executed evidence | Open acceptance |
| --- | --- | --- |
| E11 CVE detail | PASS. Same-release DuckDB/Athena detail parity for Peru scope, including CISA guidance. Eight queries scanned 5,488,587 bytes. | Query log in `data/evidence/final/athena-detail.log`. |
| E17 Nova Micro mitigation | PASS on the local HTTP boundary with real Nova Micro Converse inference. Two same-CVE Canada-scoped cases grounded 7 of 7 claims against pinned records. | Hosted CVE card to mitigation also emitted a live Nova Micro report. See below. |
| E18 Registration | Local policy tests confirm verified email remains pending and browser tokens are client-bound. | Native Chromium registration and email delivery verified. Email confirmation and a completed Google login require a mailbox or Google account owner. |
| E19 Administrative authorization | Local RSA-signed fixture checks verify pending denial, current Cognito group and MFA, all four decisions and atomic audit. | The private invite and explicit group assignment are deployed. Owner MFA enrollment and hosted admin decisions are pending. |
| E20 Revocation and recovery | Local fixture checks reject a pre-suspension token after suspension and restoration, and reject the logged-out session. | Real browser logout passed and revoked the previous access token. The recovery page rendered, while the email-code challenge remains pending. |
| E21 Direct service and owner isolation | Prior G6 baseline covered real AgentCore workspace/owner separation. The new local gateway checks deny unapproved accounts and mismatched subjects. | Hosted pending user blocked at CloudFront API and direct AgentCore. Peer replay on the approved path returned an invalid cursor in the peer namespace. |

Live Nova Micro cases saw first browser-independent HTTP events at 7.95 and
8.61 ms, full local streams at 1,059.22 and 730.10 ms, and Converse calls at
795 and 466 ms. Observed usage was 444 input and 100 output tokens over two
requests. The adjudicator matched evidence identifiers, source records,
checksums and text. This is local live-model evidence and uses a different
denominator from the historical 22 of 22 deterministic checks.


## Hosted production evidence

The assigned workspace is [AEGIS on CloudFront](https://d13u8qrh8t434t.cloudfront.net).
The first hosted browser case passed TLS, login with S256 PKCE, pending
status, absence of stored tokens, unauthenticated admin refusal and pending
denial at the API and direct AgentCore. The controlled native account
registered through the frontend and Cognito delivered its code. The connected
mailbox withheld the code from automation. Direct registration of the
reserved administrator email was rejected by the live pre-sign-up trigger.
The Google route reached its real sign-in page and no federated user was
observed at the acceptance check.

The approved browser session loaded the pinned Iceberg release. Canada
returned the qualified network context and Peru returned unavailable context.
The geographic exposure list was empty in both scopes. The selected
relationship opened its CVE card. The real managed response produced nine
ordered events and one completed terminal event. The finished report emitted
4 of 4 supported factual claims, independently compared to the archived
source records and checksums. The first response headers arrived in 2,029.22 ms,
the visible progress in 2,996.45 ms, and the report in 16,216.16 ms. Nova Micro
spent 448 ms and used 222 input and 59 output tokens, estimated USD 0.00001603.
The owner replayed the exact suffix. The browser test's initial peer assertion
expected 404. AgentCore actually wrapped 409 for the absent peer-owned cursor,
consistent with its owner-derived namespace. The captured peer response
contained no investigation result.

The Lambda startup correction recorded one cold report with 9,817.23 ms of
initialization and 30,199.66 ms of invocation. Two warm API auth refusals took
2.24 and 1.89 ms of Lambda execution. Client HTTP observations were 669 ms
through CloudFront and 309 ms through the direct API. These service and client
measurements are distinct.

The isolated session test passed in 40.1 seconds. It verified a live cancel
request returned 200, the stream emitted exactly one `cancelled` terminal
event, a peer could not cancel the owner's journal, and a browser logout
invalidated the old API token. Its evidence is
`data/evidence/final/production-session-checks.json`.

Final G7 remains blocked on permanent-administrator activation and
administrative lifecycle verification in the browser, native mailbox
confirmation and password reset, and a complete Google federation flow.
The owner can complete these checks without changing infrastructure or
sharing authentication secrets. Notifications and geographic source-dependent
positive cases remain outside mandatory activation.

The deployed Cognito challenge check used a disposable native identity and
verified both `NEW_PASSWORD_REQUIRED` and an enforced subsequent TOTP
challenge. The account was disabled. This evidence exercises the same pool
and client used by the permanent administrator, whose private onboarding
remains pending. [Execution record](../STATUS.md)
