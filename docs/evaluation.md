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
| E18 Permanent administrator authorization | The owner authenticated as the reserved native administrator. Independent hosted inspection showed the protected directory and activation audit. Cognito and the application confirmed the enabled subject, verified email, live administrator membership, preferred TOTP and APPROVED decision. | The ordinary decision workflow still needs an authorized hosted action. The permanent account exposes only its audit action. Local API regression verifies a suspension request for it is refused. |
| E19 Native registration and email confirmation | Chromium submitted a dedicated email registration and reached Cognito's verification challenge. Native sign-in and a pending account's access restrictions were exercised with an operator-created fixture. | Complete mailbox confirmation and sign-in for the actual public signup. |
| E20 Google federation and pending approval | The hosted Google entry point and Cognito redirect are configured. The local signed-token regression verifies a matching email and a group claim confer no administrator access. | Complete a real Google login with a controlled validation identity, then verify its pending status, ordinary workspace approval and revocation. |
| E21 Administrative approval and rejection | The local signed-token API test verifies both transitions and rejects an ordinary user's approval request. | Approve and reject distinct disposable accounts through the hosted administrator interface. |
| E22 Suspension, restoration and token revocation | The local API confirms that a suspended token stays revoked after restoration. Hosted cancellation and browser logout completed and the API refused the logged-out token. | Exercise hosted suspension and restored access with a fresh token and confirm the pre-suspension token stays denied. |
| E23 Password recovery and logout | A real hosted browser logout revoked the old access token. The Cognito recovery form was previously observed. | Complete the actual mailbox recovery challenge and verify sign-in with the changed disposable password. |
| E24 Administrative privilege escalation prevention | Hosted assertions deny a pending user's admin reads and an approved ordinary user's request with an administrator header and role field. The signed-token regression rejects substituted subjects, wrong clients, wrong token types and untrusted group claims. | The hosted administrator's privileged mutation checks remain open. |
| E25 Administrative audit integrity | The hosted protected audit and stored decision both recorded the permanent account's activation with actor, target, UTC time and applied outcome. The local regression verifies the audit created by each lifecycle transition. | Verify audit entries for the disposable approvals, rejection, suspension and restoration in production. |

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

### Production acceptance rerun, 24 November 2026

All three combined Chromium cases passed in 2.3 minutes against the assigned
CloudFront URL. The corrected journey verified the CISA record rendered
from the CVE detail and independently read the same evidence ID from the
authenticated API. The identical route refused an anonymous request. This
tested the UI's evidence cache and the server's authorization separately.
The combined run also exercised world, Peru and Canada filters, the
relationship graph, live mitigation, exact owner replay, denied peer
replay and cancellation, an editable handoff with no outgoing POST,
explicit cancellation, and browser logout with old-token refusal.

| Measurement | New observation |
| --- | --- |
| Local regressions | 73 Python tests and four frontend contract tests passed. Lint and type checks passed. |
| Hosted grounding | 4 of 4 factual claims supported by independent archive records, 100%. |
| Hosted timing | Response headers at 14.57 s, first visible progress at 15.39 s, report at 27.39 s. This browser run did not isolate Lambda cold and warm timings. |
| Live model | One Nova Micro call, 534 ms, 222 input and 59 output tokens, estimated USD 0.00001603. |
| SSE | Nine ordered mitigation events and one completed terminal event. The independent cancellation stream emitted one cancelled terminal event. |
| Disclosure and external actions | No unauthorized disclosure or outgoing handoff submission in the tested cases. |
| Geography | Zero CVE geographic observations emitted. Historical Canadian network context was independent of the unavailable CVE exposure, and Peru network context was unavailable. |
| Bundle and storage | Three production documents and 36 referenced assets, 6,044,554 bytes in total, produced no access-key, private-key, source-map or loopback API marker. No persisted access or refresh token was found in the tested browser sessions. |
| Token expiry | The live account endpoint refused the original signed fixture token with HTTP 401 after its expiration. |

The accepted release was `4e13ca6b-c2e1-4407-88bc-c362da7dbacb`.
The historical local deterministic 22/22, local live 7/7, historical
hosted live 4/4 and new hosted live 4/4 denominators remain separate. The
previous Athena detail parity remains eight queries and 5,488,587 scanned
bytes. The browser test did not collect a new authoritative Athena scan
total. Evidence and production images reside in
`data/evidence/production-acceptance/`.

Final G7 remains open on the hosted administrative lifecycle, native mailbox
confirmation and password reset, and a complete Google federation flow.
Notifications and geography cases that require additional qualified source
data remain outside mandatory acceptance.

The deployed Cognito challenge check used a disposable native identity and
verified both `NEW_PASSWORD_REQUIRED` and an enforced subsequent TOTP
challenge. The account was disabled. The permanent administrator later
completed onboarding and accessed the hosted dashboard. [Execution record](../STATUS.md)

## V2 acceptance increments

| Case | Verification | Outcome |
| --- | --- | --- |
| V2-E01 Official vulnerability source counts | Compare KEV declared count, digest-verified annual NVD arrays and verified CVE ZIP member counts with Parquet and DuckDB totals. | Local pass for the pinned artifacts. KEV 1,792/1,792, NVD 440,131/440,131 file records, CVE Program 431,604/431,604 file records. |
| V2-E02 Resumability and synchronization | Validate byte-resume and receipt contracts. Reuse existing files on the live official-source rerun. Reconcile older NVD cursors using the annual feeds. | Local pass. Current NVD and CVE distinct counts reproduced. |
| V2-E03 Source discrepancies | Keep each payload, reconcile published IDs and report unshared IDs and missing enrichment. | Local pass. 431,100 joined CVEs, with 14 NVD-only and 19 CVE Program-only. |
| V2-E04 KEV history | Compare official Git revisions, retain invalid inputs and recheck committed segments. | 347 of 348 source revisions validated. One malformed upstream revision is reported. |
| V2-E05 EPSS history and models | Inventory daily manifests, resume a bounded tranche and verify score changes at model boundaries. | Latest day and 43 of 2,041 available historical dates verified. Full history is blocked on local storage. |
| V2-E06 Worldwide registration and geography | Measure registry coverage with qualified sources, validate country and regional codes, distinguish registration, inference, observation and missing coverage. | The local ITU subscription metric has values for 151 economies in 2024, with separate nulls and source-reported zeros. The NRO audit verified all five registries and 240 published registration codes. Inference and observed CVE geography remain pending. |
| V2-E07 Scale, privacy and cloud parity | Measure local and cloud query costs, compare a pinned Iceberg release, verify isolation, license constraints and browser performance. | Planned for V2.5 and V2.8. |
| V2-E08 Agent grounding | Measure supported factual claims with a denominator and verify attribution of observations and inferences. | Planned for V2.7. |

[V2 ingestion measurements and cost estimates](v2-ingestion.md)

The local DuckDB NVD/CVE overlap query matched 431,100 IDs in 549.05 ms
on its first connection query and 381.92 ms on repeat. The operating
system cache was not controlled. These measurements cover local Parquet
only. [Execution record](../STATUS.md)

### V2 cloud and analytical canaries

| Case | Executed evidence | Result |
| --- | --- | --- |
| V2-A approved scope and immutable storage | Local integration and SDK-stub contract checks. The migration dry run verified 572 unique objects. Local migration verified 130 EPSS objects and reused its manifest. | Local pass. Actual AWS object storage and the cloud canary are pending. |
| V2-B direct provider, resume and source gaps | One actual 410,485-row EPSS date committed in local Bronze. A replay and migrated date reused committed objects. Attempt tests covered failure, retry and replay. | Local pass on the selected date and prior artifacts. Full dates pending. |
| V2-C snapshot, model and pruning | Three pinned Silver components across eight dates. Single-CVE values matched DuckDB source files on eight observations. One queried week had five manifest-confirmed gaps. The June model transition left the daily change null. | Local pass on those samples. Athena scans and the combined V2 release remain pending. |

The 1,022,253-row June component took 2.62 s to build and 533,463,040
bytes maximum RSS. Its history query took 53.24 ms on first read and
10.43 ms p95 across 20 repeats. The November and 2021 samples had warm
p95 of 8.66 and 6.70 ms. The OS cache was uncontrolled. The query planner
selected 3, 3 and 2 data files respectively, at 10,819,067, 13,005,022
and 620,280 physical bytes. These are local file totals. Athena billed
bytes, cold Lambda latency, cached API latency, V2 browser visualizations
and agent grounding were not evaluated in this increment.

[Time-series contract](timeseries.md) · [Execution record](../STATUS.md)

The first EPSS Gold projection materialized three daily rows in 3,002
bytes from 1,022,253 Bronze observations. An independent DuckDB read of the
original Parquet matched its counts and probability statistics. Initial
build time was 2.66 s with 305,627,136 bytes maximum RSS. The local
projection read took 1.121 ms first and 0.824 ms p95 over 20 repetitions
with uncontrolled OS cache. Replay reused the identical file digest.
