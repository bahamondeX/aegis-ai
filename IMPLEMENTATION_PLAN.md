# AEGIS AI — 48-hour implementation plan (continuation)

## Revision summary — what changes and what remains

**Changes:** extend G5 with a globally usable map, independent network-context and CVE-geography layers, explicit evidence and uncertainty semantics, and a complete CVE-to-mitigation journey. Correct the stale G6 status to partially verified: Cognito and AgentCore are deployed, but frontend hosting, the standalone cloud API and hosted authenticated end-to-end verification remain outstanding. Extend G7 with geographic correctness, privacy and mitigation-journey tests. Make source-dependent geographic observations a conditional deliverable, not a prerequisite for all frontend work.

**Preserved:** G1–G3 remain closed; G4 remains closed after successful live Nova Micro inference; the Nuxt 4 baseline of G5 remains closed. Preserve the verified CISA KEV/FIRST EPSS/NVD ingestion, immutable evidence and releases, DuckDB/Athena parity over Iceberg, typed REST/MCP contracts, four-node LangGraph, SSE, deterministic fallback, authentication, isolation, deployment guards, original evaluation requirements, scope reduction, operational runbooks and cleanup policy. No Qlik, new always-on infrastructure, fabricated data or unapproved spending.

`AGENTS.md` remains the governing contract. If an implementation increment would require a new canonical schema, endpoint, MCP tool, event contract or a change to an existing security boundary, document the proposed compatible extension and update the relevant contract through the normal review process before implementation. Do not silently override `AGENTS.md` with this plan.

## Execution and schedule

The original 48-hour windows are elapsed-hour targets, not promises or evidence of completion. Do not restart the sprint clock or reexecute completed gates. Continue from the last verified commit; record actual elapsed time and work remaining in `STATUS.md`. Parallelize independent read-only discovery and local work where useful. Stop unauthorized cloud writes, not independent local development. Apply the bounded correction loops, lockfiles, native ARM64 tooling and evidence requirements in `AGENTS.md`.

| Original window | Gate | Status at this revision | Deliverable / remaining work |
|---|---|---|---|
| H0–H5 | G1 | PASS — local | Real ingestion, DuckDB, schema and evidence; preserve |
| H5–H11 | G2 | PASS — AWS | CDK, Iceberg, Athena parity, scheduled ingestion; preserve |
| H11–H17 | G3 | PASS — local; additional query parity verified in AWS | FastAPI and typed MCP tools; preserve |
| H17–H23 | G4 | PASS — live Bedrock | LangGraph and grounded SSE with fallback; preserve |
| H23–H34 | G5 | PASS — closed | Nuxt 4, independent network context and CVE mitigation verified in `4d8c092` |
| H34–H42 | G6 | Deployed — permanent administrator and combined browser smoke verified | Complete hosted identity decisions, native confirmation and recovery, Google federation and fixture cleanup |
| H42–H48 | G7 | Local, live Athena, live model and combined hosted smoke verified — final acceptance pending | Finish E18–E25 identity acceptance and record verified cleanup |

Resume from `690555e`, `a0b6e40`, `32be230`, `5d16f77` and the latest verified execution in `STATUS.md`. Close the remaining G6 identity acceptance, then reconcile the final G7 evaluation. Preserve unavailable or pending conditional source outcomes. Keep G1–G5 closed.

### Scope tiers and completion reporting

| Tier | Deliverable | Completion rule |
|---|---|---|
| Mandatory MVP | World map, global/country filters, independent network context when an approved source exists, evidence-aware CVE card, mitigation chat, existing analytics/agent functionality, secure hosted UI/API and acceptance tests | Verify the complete working journey with real data. If no network-context source is approved, show and explain that layer's unavailable state; record data enablement separately. Map outlines alone do not constitute operator coverage. |
| Conditional geographic deliverable | First nonempty CVE-geography layer from reusable, authorized aggregates or appropriately scoped authorized inventory evidence | PASS only when real observations, permission, provenance, spatial precision, coverage and rendering are verified. Otherwise record UNAVAILABLE, PENDING SOURCE APPROVAL or BLOCKED with reason. The mandatory frontend can pass independently. |
| Optional extension | Private site-confirmed asset findings, explicit SOC incident layer and further sources | Implement only with actual authorization, a real inventory/telemetry source and verified isolation. If not enabled, mark NOT IMPLEMENTED or UNAVAILABLE; do not imply acceptance. |

A gate may report its mandatory scope as PASS while a conditional or optional component remains unavailable. Always publish the separate statuses. A failed mandatory test is not a PASS, and a functional base map is not proof that a geographic data layer is populated. Do not represent missing coverage as zero exposure.

## G1 — Data first [PASS — CLOSED]

Preserve the verified local pipeline and its original acceptance criteria:

1. Python 3.12 via uv, locked Polars, PyArrow, DuckDB, PyIceberg, httpx, Pydantic, pytest, Ruff and dotenv dependencies; immutable raw captures, normalized Parquet and reproducible DuckDB views.
2. Real CISA KEV and daily FIRST EPSS, schema/date/checksum/provenance validation; bounded incremental NVD enrichment (up to 20 KEV CVEs per run under the verified implementation), persisted cursor, missing coverage, CVSS/CWE/CPE relationships and evidence. Retain documented source limits; avoid a full NVD download.
3. Optional Shodan capability check, no host enumeration, no quota circumvention, no secrets in output. Geographic exposure only from authorized observations or permitted aggregates; otherwise retain the empty exposure table and coverage reason. Do not derive exposure from advisory URLs or ASN registration.
4. Shared SQL and DuckDB views for ranking, coverage, graph and geography; uniqueness, source links, date types, null semantics, idempotence, manifests and actual query results. Preserve original same-snapshot verification using `make verify-phase1` twice.

**Verified baseline:** `STATUS.md`, G1 PASS (2026-11-23T23:45:23Z), pinned release `4e13ca6b-c2e1-4407-88bc-c362da7dbacb`. 1,792 KEV entries; 411,399 EPSS scores and complete EPSS matching for that KEV cohort; 20 of 20 requested NVD records returned for the pinned capture, 40 enriched across two batches; 5,016 graph edges in the reported query; zero geographic observations with unavailable coverage. Original verification: 22 tests and reproducible Parquet/query results. These are historical snapshot metrics, not current feed totals.

**Disposition:** closed. Any additional geographic/context ingestion is a G5 increment with regression coverage, not a new G1 gate. Preserve existing captures and publish compatible, independently validated new releases if needed.

## G2 — Lakehouse and infrastructure [PASS — AWS, CLOSED]

Preserve the Python CDK deployment, private KMS-encrypted S3, Glue catalog, Iceberg v2 tables, Athena engine 3 workgroup and 64 MiB query cutoff, scoped IAM, SSM, Lambda Linux ARM64 and six-hour EventBridge Scheduler. Continue to use compatible packaged native libraries, CDK synth/diff, approved bootstrap and project-specific identifiers. Maintain single-writer/optimistic-locking semantics, immutable archive and release manifests, pinned table versions, idempotent publication and rollback recovery. Never remove active Iceberg files through blind lifecycle policies.

**Verified baseline:** `a63a46f`; `STATUS.md`, G2 PASS (2026-11-24T02:04:37Z). Two seed publications returned the same eight Iceberg snapshot IDs. Pinned, manual and scheduled releases matched DuckDB in the reported 42 parity checks. Manual ingestion succeeded before Scheduler was enabled; scheduled ingestion, encryption, scoped permissions and workgroup limits were verified. Existing Glue database, KMS key, bootstrap and ECR assets were retained. Final billed cost was not measured.

**Original acceptance preserved:** `make synth`, `make diff`, `make verify-cloud`, real publication and scheduler verification. Do not rerun deployment or recreate tables merely because the plan changes. Use targeted parity and regression tests for new schema/query increments; perform cloud reads/writes only within applicable remaining authorization. See `docs/lakehouse.md` for the existing runbook.

## G3 — API and MCP [PASS — CLOSED]

Preserve FastAPI, Pydantic v2, typed DuckDB/Athena adapters, allowlisted parameterized reads, authentication, workspace and owner isolation, query budgets, stable ordering, typed errors, provenance and source freshness. Retain the seven original REST routes and six official-SDK-verified MCP tools defined in `AGENTS.md`; do not expose arbitrary SQL or unrestricted network/command tools.

**Verified baseline:** `ff203dd`; `STATUS.md`, G3 PASS locally (2026-11-24T02:13:23Z): 32 tests and seven authenticated HTTP routes/six MCP tools over real DuckDB. Subsequent G4 Athena parity verification matched all six additional G3 query cases, with seven queries scanning 10,210,468 bytes. The standalone production API and hosted browser integration are still G6 work, not part of this PASS.

**Original acceptance preserved:** `make test`, `make smoke-local`, official MCP discovery and actual tool calls, invalid filters, missing evidence, no-geography semantics, limits, auth isolation and stable ordering. Add backward-compatible typed read contracts if necessary for G5; version schema and test both adapters, client compatibility and isolation. Keep existing API and tool behavior intact, including geographic queries returning unavailable rather than global rankings for a regional request.

## G4 — Agentic workflow [PASS — LIVE BEDROCK, CLOSED]

Preserve the deterministic four-node LangGraph (`plan`, `research`, `analyze`, `validate`), six typed MCP tools, bounded retry/revision, trace correlation, checkpoint and SSE journal, owner-bound idempotency, cancellation, replay, typed filter proposals and evidence-grounded reports. Preserve `amazon.nova-micro-v1:0` as the verified configurable model in `us-east-1`; do not switch models or introduce unbounded tool use merely for the map extension. No raw chain-of-thought or automatic side effects.

**Verified baseline:** `cbd82bf`; `STATUS.md`, G4 PASS with live Bedrock (2026-11-24T03:18:31Z). Live Nova Micro Converse smoke returned cited claims on the pinned release; cancellation-loop smoke first SSE event 13.38 ms and completion 1.73 s (rounded). Budget-denial smoke produced eight grounded deterministic fallback claims, zero model usage entries and a terminal event. The Peru request correctly reported unavailable regional exposure without substituting global risk. At G4, 55 Python tests passed; throttling/timeout recovery was tested with SDK stubs, not observed as a real provider throttle.

**Original acceptance preserved:** live model inference grounded in actual evidence, valid filter proposal and terminal event, typed SSE with heartbeat, global/regional behavior, invalid inputs, source prompt injection, timeout/disconnect and evidence consistency. Keep these as regression requirements. Add mitigation and geography semantics to the existing bounded workflow in the G5 extension, with tests; do not rebuild G4, claim live inference from fallback, or replay paid calls unnecessarily. See `docs/g4-investigations.md`.

## G5 — Frontend [PASS — CLOSED]

### G5 baseline — retain the verified implementation

**Verified baseline:** `94eebd0`; `STATUS.md`, G5 PASS on Nuxt 4 (2026-11-24T03:42:10Z). Nuxt 4.7.0, Nuxt UI 4.13.1, Tailwind CSS 4.3.0, native Node 22.22.3 and pnpm 10.32.1 are the recorded versions. The existing authenticated command center has globe.gl, MapLibre, an evidence-bound deck.gl overlay, Cytoscape, ECharts, ranked CVEs, evidence drawer and synchronized investigation filters. Production-mode local build, strict type check, four TypeScript tests, two local Chromium tests and one additional Chromium Cognito/AgentCore smoke passed. Snapshot replay passed 56 Python tests. The Cognito browser smoke ran before final map/display refinements; it is not proof of hosted UI acceptance. Existing screenshots are under `data/evidence/g5/`. The corrected tactical canvas showed country outlines and unavailable exposure, not populated operator coverage or CVE observations.

Do not restart Nuxt or discard the base implementation. Keep lazy-loaded client-only WebGL views, bounded feature/node counts, explicit map container size, worker assets, cleanup, accessibility, responsive panels, reduced motion, fallbacks, typed shared filter state and atomic SSE updates that preserve manual user overrides. Keep real data, honest coverage states and provenance. No attack animations or fictional arcs.

### G5.1 — Geographic semantics and layer contract (mandatory)

World view is the default. All countries share the same data and query policy. Peru (`PE`) is one normal country filter, never a hardcoded special case. Support global-to-country drill-down, and region drill-down only where evidence has that resolution. Use attributed real boundaries, consistent globe and tactical-map semantics, and separately selectable network and CVE-evidence layers. The basemap is not a data source of vulnerability exposure.

#### Independent layers

| Layer / visual state | Qualification | Geometry and behavior |
|---|---|---|
| Network context — neutral blue/slate outline, hatch or fill | Published and reusable operator/regulator evidence of presence or coverage in an explicit country/region; alternatively ASN country-of-registration only, distinctly labeled `País de registro` / `Country of registration` | Area only, never router pins. Visible independently of selected CVE and its exposure availability. Registry geography is not operational presence. No red/amber affected styling merely because an operator is present. |
| CVE evidence — amber, `Ubicación estimada` / `Estimated location` | Authorized, publishable-as-applicable, CVE-specific aggregate tied to a stated zone with approximate spatial precision | Draw the documented area, not a centroid/point pretending to be an asset. Show source, date, unit, coverage, scope and precision. Do not distribute an ASN total across its registered country or all operating countries. |
| CVE evidence — checkmark (`✓`), `Ubicación verificada` / `Verified location` | Private, authorized finding linked to an inventory-confirmed site, with permission for the current user/workspace | Point only for a confirmed site at allowed precision; if only a region is confirmed, use its area. The checkmark verifies location, not exploitation or a confirmed incident. Optional extension; absent until qualified. |
| CVE evidence — gray, `Sin datos de exposición` / `No exposure data` | No applicable observation or coverage; retain typed reason and distinguish failed/stale source from unsupported scope | No fabricated point or exposure intensity. Keep CVE card and network context accessible. Distinguish unavailable coverage from a source's valid measured zero. |

Reserve red for vulnerability severity (for example, CVSS severity on the card/graph), not location verification or absence of evidence. Reserve `★` for a user-starred finding, never source authority. Use text, symbols and accessible patterns as well as color; separate severity and geography legends. A measured zero should have an explicit numeric `0`, source, interval, unit and valid coverage; it must not be visually or semantically confused with unavailable/null. Missing values are not assumed zero. Do not depict inferred incident directions, victim locations, router positions or fabricated heatmaps.

An ASN identifies a network, not a unique router or default gateway. Do not derive location or exposure from a supposed main gateway, router IP, vendor headquarters, ASN registration, network/mobile coverage, DNS resolution of advisory domains, CISA/NVD reference URLs or an operator's country of incorporation. GeoLite2/IPinfo may enrich an existing authorized observation only within license and documented precision; they are not sources of CVE exposure.

#### Evidence categories and analytical meaning

Keep category and location confidence as independent dimensions in storage, API, legend, KPIs and agent responses:

| Category | Meaning | Rule |
|---|---|---|
| Observed exposure | A source observes a service/asset associated with a CVE, with its documented detection method and limitations | Report the source's actual unit and claim; not automatically exploitation or an incident. |
| Sensor-detected attempts | A sensor reports an attempt under its documented measurement definition | Label sensor/observation geography as such, never victim geography. An attempt is not proof of compromise. |
| Confirmed incident | An authorized SOC/CSIRT incident record with confirmed scope and location where available | Optional private layer with separate incident permissions and provenance. Do not infer victim location from a source IP or sensor location. |

CVSS describes severity; FIRST EPSS estimates the probability of exploitation in the next 30 days (not a country's attack probability); CISA KEV records known exploitation (not its regional occurrence or current incident count). These global vulnerability attributes remain available in the CVE card even without regional evidence. Regional analytics must not silently substitute global ranking or create a local risk conclusion from these attributes alone. If a user asks about Peru, distinguish global CVE facts from actual Peru evidence.

### G5.2 — Source qualification and data/API increment

Run source discovery independently of local UI work. Prioritize (a) published, reusable operator/regulator country or regional coverage/presence for network context, and (b) a real inventory explicitly authorized for AEGIS or an aggregate dataset with reuse rights for CVE-specific exposure. The two qualification tracks are independent; success in one does not imply success in the other.

Shadowserver or another aggregate provider is a candidate, not an integrated or approved source. Before ingesting or publishing any figures, record the source URL, redistribution/derivative-use permission (public vs private), methodology, observation unit, CVE attribution method, timestamp and interval, sampling/coverage, geography definition and precision, scope and restrictions. If any required qualification is missing, do not copy the figures or enable its exposure layer; provide a clearly labeled link to the original public dashboard where appropriate. Do not assume free access implies reuse permission. Shodan Free remains optional; no subscription, quota circumvention, host enumeration, scanning or collection of third-party target lists. Never manufacture coverage by querying random IPs or ASN ranges. No new provider spending or deployment without applicable approval.

Maintain a source register with `candidate`, `qualified`, `unavailable`, `blocked_permission` and `enabled` (or equivalent explicit statuses). A source is enabled only after license, provenance, schema, real records and publication-safety checks pass. Capture permitted raw bytes or allowed subsets, checksums, source URL, fetch time, source data date, methodology/terms reference, coverage and schema version as required by `AGENTS.md`. Keep restricted source records private. Untrusted advisory text is input data, not agent instructions.

#### Compatible data contract (proposed increment, not yet implemented)

Preserve the existing eight canonical tables and their pinned historical releases. Reuse `fact_geo_exposure` and `evidence` where their semantics fit; do not insert registry/presence records into exposure facts. Add a versioned network-context relation or companion dataset and compatible coverage metadata only when needed. Use nullable, typed fields; the following are logical requirements, not preexisting table names or API fields:

| Contract | Required semantics |
|---|---|
| Network context | Stable record/operator identifier, optional ASN, context kind (`operational_presence`, `published_coverage`, `registration_country`), country ISO2/region, documented area/geometry reference, effective/source/retrieved dates, coverage/scope, source evidence and license/publication status. No CVE association inferred. |
| CVE geography | CVE identifier, observation category, geographic scope/role, country/region or authorized site reference, precision/confidence, count nullable, unit, measurement interval, coverage status/reason, source/evidence identifier and access/publication scope. Preserve `fact_geo_exposure` grain and existing uniqueness; extend/version explicitly if new grain is required. |
| Coverage | Distinguish `observed` (positive measured value), `measured_zero` (valid source coverage and explicit zero), `unavailable` (no applicable coverage), and error/stale/partial metadata. Include the source, CVE/cohort, zone, interval and scope to which coverage applies. A count of null is not zero; partial coverage must not be generalized to a whole country. |
| Private site finding (optional) | Authorized inventory/site reference, matching finding/CVE evidence, confirmation method/date, precision and owner/workspace access scope. Keep exact geometry restricted and separate from public aggregates. No raw third-party targets. |
| SOC incident (optional) | Authorized incident reference, incident status and evidence, confirmed affected location if present, relevant event date, access scope and distinct observation category. Sensor and source-IP geography remain explicitly separate. |

Use real country/region boundaries only at the source's stated resolution. Do not invent coordinates or extrapolate total counts. Do not sum overlapping source windows or unlike units, or present service counts as unique hosts. Preserve source dates and attribution for every record; identify records with unknown geography without forcing coordinates. Keep context and exposure joins explicit, never generate a CVE-by-country cross product from operator presence. Exclude public ASN/CVE drill-downs that reveal targetable infrastructure; public context remains non-CVE-linked.

If extending storage, define versioned schema migration and release-manifest compatibility before writing. Retain old eight-table manifests and read semantics; do not mutate historical snapshots. Build/validate locally with Polars, Parquet and DuckDB, then use the shared allowlisted SQL and minimal dialect adapters for Athena. Verify key uniqueness, null handling, scope consistency, evidence references, source permission, no cross-tenant rows, replay/idempotence and parity on the same release. Only publish qualified real records under appropriate AWS authorization. Unavailable optional source data must not stop the existing required CISA/EPSS/NVD pipeline.

#### API, privacy and snapshot consistency

Extend the existing `/v1/map`, `/v1/coverage`, `/v1/cves`, `/v1/evidence/{id}` and corresponding typed contracts where compatible. Keep the six existing MCP tools; use a minimal reviewed extension or typed read tool only if necessary. `get_exposure_by_country` must continue to report exposure, not network presence. Do not reinterpret an existing field in a breaking way; update schema/version and generated TypeScript validators together. All geographic responses carry release/snapshot identity, source coverage, category, scope, unit, precision and evidence IDs. Bind approved context-data version to the selected release or a deterministic companion manifest; no silent live mixing of datasets. Validate geographic identifiers and filters server-side.

Derive authorization from the validated principal, not browser flags, client-supplied workspace or raw filter proposals. The public-safe projection may expose only approved aggregate observations and approved non-CVE-linked network context. No IPs, third-party asset lists, exact locations, restricted provenance payloads or targetable CVE/ASN drill-downs. If no public view is approved or deployed, keep all routes authenticated and verify the public-safe projection independently; the invite-only access policy remains in force. Do not open new anonymous routes to satisfy the word "public". Private site details require both workspace membership and record/site access checks. Enforce scope on REST, MCP, SSE, graph edges, evidence links, caches, exports, reports and replay. Apply aggregation/suppression as required by source terms or reidentification risk. Never serialize private geometry into a public payload and hide it with CSS. Do not log secrets or private locations in shared evidence artifacts. Use cache keys including snapshot and effective authorization scope.

### G5.3 — CVE-to-mitigation journey (mandatory)

Implement a vertical slice on the existing Nuxt command center:

1. Open the globe in world view, choose a country/region or select a CVE node in the graph (the CVE table remains an accessible fallback). Select a CVE from an actual exposure feature when available, or from the graph/list independently of map exposure. Never infer a regional association from a graph selection.
2. Open one evidence-backed CVE detail card. Show identifier, description, vendor/product, affected version/configuration conditions with source references, CVSS score/version/source, EPSS score and score date, KEV status and catalog evidence, and relevant geography/coverage separately. Distinguish confirmed product applicability and versions from candidate matches, unknown versions and missing NVD enrichment. A CPE entry alone is not proof a specific deployed asset is vulnerable. Missing CVSS or version data stays unknown.
3. Select `Cómo mitigarlo` / `How to mitigate`. Launch or prefill an authenticated investigation using the selected CVE, same release, current filters and relevant evidence IDs. The shared store binds map, graph, detail card and chat to the same snapshot/filter revision. Preserve manual overrides; reject stale SSE events and cross-snapshot proposals. Show any change of scope explicitly. If a snapshot is no longer readable, surface an explicit refresh/reselect path, never silently change evidence.
4. Use the existing four-node workflow to retrieve and validate vulnerability evidence and approved vendor advisories. Recommend patches, fixed versions, workarounds and applicability conditions only where the evidence supports them. Cite the evidence ID or verified manufacturer advisory, differentiate a recommended patch from verified installation, identify unknown asset/version/region facts, and state what the user should confirm. If no reliable mitigation is available, provide the verified reference and state the limitation rather than invent a fix. Keep actions advisory and read-only; no exploitation, scanning, automatic patching or arbitrary agent network/SQL calls.
5. Select `Pedir ayuda` / `Request help`. Generate a reviewable, editable handoff summary for the user's SOC or appropriate CSIRT: CVE, known scope, evidence, applicability uncertainties, mitigation recommendation, urgency rationale and explicitly authorized details. Use safe defaults and omit private coordinates/identifiers from any public-safe summary. The user reviews and chooses whether to copy/export. No automatic send, external ticket creation or case opening. FIRST is a directory of teams; link to an appropriate directory entry only when supported, never treat FIRST as a dispatch desk or promise a response.

Retain the existing SSE envelope and event ordering defined in `AGENTS.md`; use typed, authorized extensions only when necessary. The validated report and UI state must reference the same evidence and release. If geography is unavailable, the selected global CVE card and vendor mitigation evidence remain usable; the chat explicitly declines a regional exposure conclusion while still answering supported CVE-level questions.

### G5 acceptance — extension-specific, with baseline regression

- Existing Nuxt production build, lint, strict TypeScript, Python regression/snapshot replay, API/MCP smoke and SSE/filter synchronization remain green. Use the pinned package manager and real captured feeds; do not mock the production pipeline.
- Playwright Chromium against the actual local production build and real authenticated backend: world view renders nonblank country features, filter Peru and a second available country, inspect both layer controls, legend and coverage states; responsive desktop/mobile and tactical view, no uncaught errors, usable keyboard/fallback behavior. Preserve prior browser checks.
- Browser-test `map or graph → CVE card → How to mitigate → chat → Request help` on actual captured CVE/evidence. When no qualified exposure data exists, test graph/list entry and the map's no-data path; do not invent a clickable exposure feature. Verify evidence/source links, shared snapshot/filter revision, manual overrides, validated SSE progress and report, citation matching and no external action. Record screenshots and actual measurements.
- Test that network context remains neutral and visible independently of CVE selection wherever a real qualified source exists; if none exists, verify its unavailable state and keep source enablement pending. Test semantic/style invariants in isolated, clearly labeled unit tests when the necessary real observation is unavailable. Do not expose fixtures through the demo, integration API or browser acceptance path.
- Conditional layer: only when real authorized observations are available, run browser and API checks for amber area geometry, source metadata, explicit zero vs unavailable, no cross-country extrapolation, and safe aggregate projection. Record exact qualified source/release and actual counts. If unavailable, record that positive rendering/integration acceptance was not executed; no fake PASS.
- Optional private/site layer: only with real authorized site evidence and approved access, verify checkmark/area semantics and owner/non-owner access in browser/API; otherwise keep disabled and record untested. Unit-level policy tests are still required for any implemented authorization logic. No public exact location, IP or private evidence leak.

Gate commands: retain `make lint`, `make typecheck`, `make test`, `make verify-phase1`, `make smoke-local`, `make lint-ui`, `make typecheck-ui`, `make build-ui`, `make smoke-ui` and existing frontend tests/audit as applicable. Add named extension test cases to the real suites and record commands, exit codes and evidence in `STATUS.md`; do not invent passing Makefile targets. Re-run paid smokes only where needed and authorized. G5 extension mandatory PASS requires the actual journey and required regressions, not a screenshot alone. Report conditional/optional enablement separately.

## G6 — Deployment [DEPLOYED — IDENTITY ACCEPTANCE PENDING]

### Preserve the completed AWS portion

**Verified baseline:** `15c4e94`; `STATUS.md`, authorized AgentCore portion of G6 PASS (2026-11-24T03:43:05Z). Scoped identity/runtime stacks reached `CREATE_COMPLETE`; invite-only Cognito with OAuth Authorization Code + S256 PKCE, 10-minute access tokens and workspace group; ARM64 AgentCore runtime with least-privilege role, private KMS-encrypted checkpoints, seven-day logs, 60 s idle and 120 s maximum session lifetime. Verified access-token handling, workspace/user rejection (including AgentCore's wrapped 403/404), remote SSE, exact cross-session replay and active cancellation. Three temporary validation users were disabled. Remote first event 958.26 ms; completion 28,610.92 ms in the recorded run. Six cited claims from eight evidence IDs, 14 events including one terminal result. These are measured validation observations, not universal production SLA or performance targets.

Recorded total Converse usage: 4,056 input and 660 output tokens; estimated inference cost USD 0.000234360. Local and runtime inference allocations were USD 0.05 each. These are recorded usage and estimates, not AWS invoice totals. Preserve existing bootstrap, ECR, Glue, KMS, lakehouse, scheduler, Cognito, AgentCore and security/budget guards. Do not recreate or reopen the deployed portion without a specific change and applicable authorization.

### Remaining deployment work

1. Select a supported, authorized hosting and API transport consistent with `AGENTS.md`: static/client-side Nuxt on private S3 + CloudFront OAC or explicitly approved equivalent, plus one lightweight secure API deployment with a supported streaming transport (Lambda response streaming via supported adapter, or API Gateway streaming only after support is verified). Evaluate how the existing local Nuxt proxy maps to the hosted topology; a static build cannot run a server-only proxy. Preserve secure server-side AWS access; never place AWS credentials, source keys, signing secrets or service tokens in browser bundles. No new always-on compute, Kubernetes, NAT gateway, RDS or OpenSearch.
2. Prepare IaC, build, local smoke, cost estimate and reviewed CDK synth/diff/change set. Use AWS CLI/CDK/SDK and the existing Makefile/Zero-Console rules; no AWS console. Validate STS, region, profile, tags, ownership, quotas, IAM, secrets, model access and remaining budgets before any authorized write. Reuse the deployed identity/runtime rather than creating duplicate stacks. Hosting, standalone cloud API, domain/DNS changes and any new source or paid integration require applicable explicit approval. This plan does not authorize them.
3. Extend the existing Cognito pool in place. Add public native registration and Google federation with mandatory administrative approval. Preserve PKCE, token checks, memory-only browser token handling, private buckets, TLS, CORS allowlists, rate limits, SSM SecureString, KMS, scoped roles, log retention and bounded query/inference/session settings. Allow only approved callbacks/origins. Keep investigations and private data authenticated; public-safe data access, if approved, is read-only and restricted to the approved projection. Validate both API and runtime authorization; no bypass or anonymous fallback.
4. Deploy only authorized UI/API components; test the final hosted artifact, not the local Nuxt server. Verify real browser sign-in, frontend API reads against the cloud release, MCP-backed investigation via the deployed runtime, evidence/mitigation journey, SSE first event before completion, terminal/replay/cancel behavior and logout/token expiration. Check that no local backend or deterministic-only mode masquerades as live deployed inference; explicitly distinguish authorized fallback. Verify scheduler/manual ingestion status and release compatibility without unnecessary repeat writes.
5. Verify public-safe projections and cross-account/workspace/user isolation for all implemented restricted locations, evidence and replay; if private site layer is not implemented, verify endpoints/payloads cannot expose it and mark positive site-access tests conditional. Use separately authorized validation identities; disable temporary users after testing. Inspect network payloads, static assets and browser storage for private records/secrets; verify no public IPs, exact third-party coordinates or private identifiers. Test data-source failure and unavailable geography without weakening isolation.
6. Update resource inventory, costs/estimates, retained resource and teardown rules, source register and layer status matrix: enabled / unavailable / degraded / pending / not implemented, with release and evidence. Measure hosted UI/API/SSE cold/warm latency where authorized, without conflating distinct scenarios. Document actual results and limits.

### Identity acceptance and scoped approvals

Implement the four account states, Cognito-verified email, the private initial
administrator invitation with a forced password change and preferred TOTP, and
the protected `/admin` directory with confirmation, KPIs and atomic audit.
Authorize against current state at the API and the runtime. Exercise real
native registration, Google federation, approval/rejection, recovery, logout,
suspension with an old JWT, direct-service denial and owner isolation. Keep
application tokens in memory. Follow the administrator onboarding and private
validation procedures in the identity runbook.

Existing `.env` scope: AWS account ending `6271`, `us-east-1`, profile `default`, prefix `aegis-dev`; verify actual configured target before execution. Keep `.env` Git-ignored and mode 600, preserve credentials and allowlisted settings. Do not print secrets.

| Existing authorization | Limit | Scope |
|---|---:|---|
| Lakehouse | USD 15 | Existing G2 operations and authorized bounded Athena verification |
| Bedrock | USD 5 | Authorized inference testing, with recorded independent USD 0.05 local and runtime allocations inside the ceiling; reconcile both ledgers before additional calls |
| AgentCore | USD 5 | Existing approved runtime/identity/supporting-resource validation scope |
| G6 hosting and identity | USD 5 | Scoped frontend, standalone API, identity extension and bounded validation |
| Total | USD 30 | Four independent scoped ceilings |
| Domains, unrelated DNS, additional sources and expanded runtime scope | Separate approval | No such changes in this deployment |

The ceilings are not service-wide billing hard caps or evidence of remaining balance. Check actual available authorization and usage; do not silently raise allocations, reallocate ceilings across services or assume credit/free tier. Keep the already established workload bounds and guard behavior in the runbooks; reconcile runtime attempt limits before new remote evaluations. If cost, permissions or approvals are blocked, stop the affected cloud operation, continue independent local work and report the precise blocker.

**G6 acceptance:** original `make smoke-cloud` with real authenticated hosted browser/API/SSE, no local fallback masquerading as deployed backend, verified security, scheduler and documented resources/teardown. If the full hosted path has not been verified, G6 remains PARTIAL/BLOCKED even if AgentCore is READY. Conditional geographic source availability does not prevent G6 mandatory acceptance when the honest unavailable state and safe behavior are verified. Hosting without authenticated end-to-end success is not a PASS.

## G7 — Evaluation and delivery [LIVE EVIDENCE RECORDED — FINAL ACCEPTANCE PENDING]

Preserve the original minimum 12 real-snapshot-derived evaluation cases, all critical safety/data checks green and at least 95% grounding on factual claims with explicit denominator. Extend the suite with the five map/journey cases below. Use a fixed release for reproducibility; separately record local, live Bedrock and hosted cloud results. Do not treat unit stubs as live provider results, estimated costs as invoices, or a skipped conditional case as a pass. Preserve earlier evidence/test counts; report new results only after execution.

### Required evaluation matrix

| ID | Case | Acceptance |
|---|---|---|
| E01 | Global KEV/EPSS ranking | Stable KEV-first, EPSS-desc, CVSS-desc, CVE-ID tie-break; correct nulls and scope. |
| E02 | CWE/product relationship graph | Edges backed by same-release evidence; correct bounded drill-down. |
| E03 | Unknown geography | Unavailable region does not become zero or global regional risk. |
| E04 | Invalid filters | Typed validation rejects invalid values, limits, country/region and date scopes. |
| E05 | Provenance | Every substantive supported claim resolves to retrieved evidence of the selected release. |
| E06 | Prompt injection | Advisory/source text cannot change system policy, route arbitrary tools or leak secrets. |
| E07 | Timeout / throttling / budget denial | Bounded retry, explicit grounded fallback or typed failure; report which paths are stubbed vs live. |
| E08 | Repeated request | Owner-bound idempotency, exact permitted replay; no duplicate inference or external side effects. |
| E09 | Stream disconnect/cancel | Ordered SSE, cancellation behavior, one terminal event and bounded recovery. |
| E10 | Auth isolation | Invalid/expired/wrong-workspace/wrong-owner access denied across transports. |
| E11 | Athena parity | Same-release query and grain parity; include new data/API read shapes if introduced; no arbitrary SQL. |
| E12 | UI state | Atomic validated proposals, stale event rejection, user overrides, same-release graph/KPIs. |
| E13 | World map and country filtering | Opens worldwide, filters Peru and another country using the same policy; no fake markers, nonblank geographic features. |
| E14 | Independent network context | Real approved operator presence without CVE evidence remains neutral/unaffected when selecting the CVE. If no qualified context records, verify honest unavailable behavior; positive data test remains conditional. |
| E15 | Estimated vs verified location | Real authorized approximate aggregate renders as amber area with precision/source metadata; real inventory-confirmed site shows `✓` only in authorized private view, or region area if that is the verified precision. Test positive branches only when their data/feature is enabled; otherwise record conditional/optional pending and test no leakage/fabrication. |
| E16 | Coverage and category semantics | `unavailable` is not measured zero; exposure, sensor attempts and confirmed incidents are not mixed. Test coverage contracts and no-category-conflation even when optional incident data is absent; positive measured-zero or incident examples require valid real evidence for integration acceptance. |
| E17 | End-to-end CVE mitigation and privacy | Map (if actual evidence available) or graph → CVE card → mitigation chat → reviewable help summary. Map/card/chat preserve snapshot, filters and evidence; claims cite sources, unknowns explicit; no auto send; public-safe projection and replay expose no private data. |

| E18 | Permanent administrator authorization | Verify hosted access, native identity, verified email, current group and preferred MFA. Verify protection against suspension or demotion. |
| E19 | Native registration and email confirmation | Complete Cognito mailbox confirmation and verify pending status and the API, MCP and AgentCore denials. |
| E20 | Google federation and pending approval | Complete Google authentication through Cognito with S256 PKCE, verify pending status and approve only ordinary workspace access. |
| E21 | Administrative approval and rejection | Use the hosted administrator interface to approve one disposable subject and reject a separate registrant. |
| E22 | Suspension, restoration and token revocation | Verify immediate denial, stale tokens after restoration and access with a fresh sign-in. |
| E23 | Password recovery and logout | Complete mailbox recovery and new-password sign-in. Verify logout revocation and memory-only browser tokens. |
| E24 | Administrative privilege escalation prevention | Verify ordinary and matching-email federated accounts cannot gain privilege through account fields, headers or untrusted claims. |
| E25 | Administrative audit integrity | Check actor, target, action, UTC timestamp and outcome for authorization decisions. |

For E13–E25, run actual browser tests for mandatory paths using real captured data. Positive conditional branches require qualified real observations and appropriate authorization. Isolated unit fixtures may exercise rendering/data-contract policies, explicitly labeled, never production/integration or demo data. Record unexecuted positive branches as NOT RUN / UNAVAILABLE rather than silently omitting them. If the condition becomes available, execute its positive tests before declaring that layer enabled. A mandatory invariant failure still fails G7 even if optional data is absent.

### Metrics and evidence

Record case ID, scenario, release, environment, authorization scope, command, actual outcome, evidence path and failure/skip reason. Grounding rate = supported factual claims / all evaluated factual claims, with explicit denominator and adjudication method; unsupported claims count as failures. Report claim-free correct refusals/no-data responses separately so they cannot inflate the grounding score. Require zero fabricated geographic observations, zero public disclosure of private/targetable records and no unauthorized actions. Report actual tests and sample sizes, source coverage/units, latency (first SSE event and total, cold/warm separately if measured), tool calls, scanned bytes and observed token usage with cost-estimate assumptions; never invent or generalize metrics. Reuse existing proof where valid; repeat live paid tests only as necessary within scoped approval.

### Delivery and final acceptance

Preserve README quickstart, Mermaid architecture source, data dictionary, source/license notes, cost estimates, known limitations, actual desktop/mobile/tactical screenshots, demo script, operational runbook and guarded cleanup. Add data-layer and publication-policy documentation, source qualification register, legend/coverage explanation, mitigation/handoff semantics and separate status for mandatory/conditional/optional scope. Update `STATUS.md` with exact commands, UTC times, exit codes, commits, sanitized resource IDs and next action. No raw secrets, access tokens or restricted evidence in Git or demo artifacts. Final local lint/typecheck/tests/build and actual browser smoke must pass. Full G7 closure requires the original authenticated cloud smoke when authorized and executed; if G6 hosting remains blocked, report local evaluation/delivery verified as applicable, but G7 final closure remains pending. Do not mark the conditional exposure layer or optional sites/incidents PASS without actual evidence. Do not claim production readiness or a completed 48-hour sprint without the recorded evidence.

## Operational runbook — preserve and extend existing procedures

The existing `docs/lakehouse.md` and `docs/g4-investigations.md` remain authoritative for deployed resources, recovery, existing command ordering, retention, model budgets, authorization checks and cleanup. Do not rerun bootstrap, deployment, seed publication or historical gates by default. This section describes future continuation commands, not commands executed by this plan revision.

1. Read `AGENTS.md`, this plan, latest `STATUS.md`, README and runbooks; inspect git status and existing implementations. Continue from verified work, preserve unrelated edits and avoid unnecessary dependencies. Keep verified commits `a63a46f`, `ff203dd`, `cbd82bf`, `94eebd0`, `15c4e94` as baseline references; actual current repository may be newer.
2. Local continuation: use existing `make preflight`, `make bootstrap`, `make lint`, `make typecheck`, `make test`, `make verify-phase1`, `make smoke-local`, `make smoke-investigation`, `make smoke-agent-local`, `make lint-ui`, `make typecheck-ui`, `make build-ui`, `make smoke-ui` as applicable. Use the actual existing snapshot and frontend scripts. Run new source/geometry/mitigation cases in the existing suites; inspect rendered artifacts. No cloud writes or paid inference are implied by local work. Avoid rerunning paid flags accidentally in shell reporting commands.
3. For a qualified new data increment, validate locally first, document schema/release compatibility, and only after applicable authorization use targeted `make aws-preflight`, `make synth`, `make diff` and the existing publication/verification runbook. Do not reset the lake or scheduler. Reconcile byte/operation budgets and preserve all existing table versions and security controls.
4. For G6 hosting/API, prepare and test locally before requesting the exact missing deployment scope. Execute `make deploy-ui` / `make smoke-cloud` and any reviewed API deployment target only when implemented and authorized, with actual hosted artifacts, authenticated cloud data and SSE. Reuse existing AgentCore/Cognito. Unimplemented targets must fail clearly, not emit fake success. Use scoped logs/CLI for diagnosis and the existing maximum three corrective attempts per blocker.
5. Record remaining costs, status of retained resources, disabled temporary users and all evidence. Existing `make destroy` retains lake data by default; `make purge` requires separate explicit destructive authorization. Never delete bootstrap, keys, data, secrets or unrelated resources as routine cleanup. No teardown is requested by this revision.

## Scope reduction if time constrained

Keep real CISA/EPSS/NVD data, DuckDB/Athena parity, evidence, four-node graph, SSE, a nonblank world map with country filters, independently represented network context and honest unavailable states, one relationship graph, KPI panel and the complete CVE-to-mitigation/handoff journey. Preserve authentication and data isolation for any deployment. If permitted network context exists, keep it visible independent of CVE coverage. Defer secondary tactical-view polish, optional animations (never fictional attack animations), advanced history/tenant features, additional provider integrations, private confirmed-site and SOC incident layers. Preserve already verified durable cross-session replay; do not remove it to save time. The original option to defer unimplemented advanced recovery applies only to additional capabilities, not to regressions of the existing verified behavior.

Do not defer data correctness, source permission/provenance, privacy, mandatory mitigation journey or safety gates. Do not substitute guessed geography, third-party infrastructure lists, fake source counts or synthetic demo records to populate the globe. If no qualified CVE geographic source exists, continue the mandatory MVP and document the conditional layer as unavailable; do not pass it or turn it into a blocker for all frontend work. If hosting authorization is absent, keep the working local demo and report the remaining G6/G7 cloud blocker. Any omitted mandatory item is incomplete, not a success.

## Demo script — from CVE to mitigation, then geography and evidence

1. Start with a real selected CVE in the graph (or a real CVE map feature if a qualified layer is enabled). Open its detail card. Show confirmed product/version conditions or explicit unknowns, CVSS source/version, EPSS date and probability, KEV status and evidence. Avoid picking a CVE with unsupported mitigation just to imply a complete record.
2. Click `How to mitigate`. Show the authenticated chat receiving the same CVE, filters and snapshot; watch real SSE tool progress and evidence, validated vendor-backed recommendations, version applicability and remaining uncertainty. Open the cited evidence or original advisory. Show `Request help` generating a reviewable SOC/CSIRT summary; no transmission or case is opened.
3. Switch to the world map and filter Peru and another country. Explain network context independently of CVE exposure: show only approved operator/regulator presence/coverage or registration-country areas labeled correctly, or the explicit unavailable state if no source is approved. Selecting the CVE must not turn network presence into an affected area.
4. Explain what the map knows, what it does not know, and why. If qualified real approximate exposure exists, show its amber area, source, date, unit, coverage and scope; otherwise show gray unavailable geography and the source limitation, not zero. If an authorized measured zero exists, distinguish it explicitly. Show site checkmarks or confirmed incidents only in the authorized private view with actual evidence and access; otherwise describe them as future scope. Do not imply any attack from exposure, EPSS, CVSS or KEV alone.
5. Ask: “Show the highest-priority known exploited vulnerabilities and explain the evidence.” Show global ranking and synchronized graph/KPIs. Then ask: “What exposure evidence is available for South America?” Demonstrate the honest regional answer and separation of global facts from regional observations; inspect the evidence drawer and source timestamps.
6. Close with actual local/Athena parity, live Bedrock and remote AgentCore validation, test and evaluation outcomes, verified hosting status, source limitations, costs as estimates where appropriate, and operational/teardown controls. Clearly distinguish the local demo from a hosted end-to-end PASS. Never use fixture-based screenshots as production evidence.
