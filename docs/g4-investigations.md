# G4 investigation verification and deployment prerequisites

## Workflow and recovery

The Planner reads typed filters and scope. The Researcher uses the existing
authorized MCP client and pins every result to the same release, EPSS date and
coverage. The Analyst computes the deterministic KEV, EPSS, CVSS and CVE ID
ranking. It can ask Bedrock for a bounded list of claim keys. The Validator
checks every key against matching evidence and renders the report from that
evidence. A malformed selection can trigger one further research and
analysis pass. Service errors and exhausted retries produce a grounded
deterministic report when the underlying evidence is available.

An investigation has a 45-second execution deadline, one active graph per
process, at most two concurrent MCP calls per graph, up to 12 provenance
lookups per research pass and a 32-event limit. Each Bedrock round has at
most three attempts. The SDK has two-second connect and seven-second read
timeouts. The retry loop uses exponential backoff with jitter and honors
`Retry-After` within its four-second wait limit. The store reserves the
estimated upper cost of each inference attempt before sending it.

The event journal uses owner-bound idempotency and conditional writes in
SQLite on disk or KMS-encrypted S3. It persists a bounded checkpoint after
each graph node, records ordered events and replays after the requested
cursor. An interrupted execution becomes terminal when its lease expires.
A caller can start fresh with a new idempotency key. The runtime never
repeats a paid inference from an abandoned checkpoint. S3 run records
expire after seven days. The model budget ledger stays outside that expiry
prefix. Local and runtime ledgers are independent. Allocate an explicit
portion of the approved Bedrock ceiling to each and reconcile the local
ledger before setting the runtime allocation.

The AgentCore template stages an allowlisted ARM64 container using the locked
Python dependencies. It configures a custom JWT authorizer and forwards
Authorization and idempotency/replay headers. The runtime verifies the JWT
workspace and STS account, pins the Athena release and verifies the encrypted
workgroup scan cutoff, then uses the shared workflow. Its role scopes Bedrock
invocation to the configured foundation model, Glue and Athena to the
project catalog and workgroup, and S3 access to the release, Athena results
and checkpoints. ECR authorization uses the account-wide token operation,
with layer pulls scoped to the dedicated bootstrap repository. The runtime
uses 60-second idle and 120-second maximum session lifetime settings.
[Runtime HTTP contract](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-service-contract.html)
[AgentCore forwarded headers](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-header-allowlist.html)
[Runtime role permissions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-permissions.html)

## Service verification

Use `make lint typecheck test verify-phase1 smoke-local smoke-investigation
smoke-agent-local synth-agent` for local and snapshot regression coverage.
Use `python -m scripts.verify_g3_athena` under the G2 approval to verify the
additional DuckDB query shapes against the same Athena Iceberg release.
The script checks the authorized account and enforced scan cutoff, and
bounds the query count. The evidence log records query IDs and scans.

The Bedrock control plane confirmed `amazon.nova-micro-v1:0` as active,
authorized and available for in-region on-demand text inference in
`us-east-1`. The documented API is Converse. A free tokenizer probe
returned `ValidationException` because this model lacks `CountTokens`.
Use the prompt-size reservation before calls and record actual input and
output tokens from successful Converse responses. After explicit Bedrock
approval, configure the model, rates and scoped budget, then run
`make smoke-investigation BEDROCK=1`. The smoke gate requires both actual
Converse usage and a grounded report from the real snapshot.
[Nova Micro model card](https://docs.aws.amazon.com/en_en/bedrock/latest/userguide/model-card-amazon-nova-micro.html)
[Bedrock CountTokens policy](https://docs.aws.amazon.com/bedrock/latest/userguide/count-tokens.html)

AgentCore publication and verification require separate approval, an
authorized OIDC issuer/audience/workspace, a successful Bedrock live
smoke and verified remaining G2 query allowance. Before provisioning,
verify STS, stack ownership, the bootstrap asset publisher and a
CloudFormation change set. After provisioning, verify scoped IAM and
the service-created log group's seven-day retention, and use a bounded
set of real JWT invocations to measure streaming, replay and cancellation.
Confirm the checkpoint bucket uses the expected key and that the runtime
fails closed on tokens outside the authorized workspace.

## Separate budgets

Estimates in USD for 20 development investigations in `us-east-1` use
published rate examples and assume no credits or free tier. AWS bills the
observed service usage. The application's inference ledger stops further
reservations at its configured allocation. Runtime cost requires a finite
test window and invocation count in the deployment runbook.

| Service | Estimate | Proposed ceiling |
| --- | --- | --- |
| Bedrock Nova Micro on-demand | **$0.021504** for up to 120 Converse attempts, each reserving 4,096 input and 256 output tokens at $0.035 and $0.14 per million | $5 |
| AgentCore and supporting resources | **About $0.48** for one bounded validation window and one month of image storage. Runtime uses v2 consumption as the higher estimate, with 20 sessions × 135 seconds allowing for shutdown, 2 vCPU and 8 GB charged for every second at $0.1276/vCPU-hour and $0.0169/GB-hour, or $0.2928. ECR allowance is $0.12 for up to 1.2 GB. CloudWatch allowance is $0.053 for 0.1 GB ingested and archived. A $0.01 allowance covers S3 checkpoint storage and requests. | $5 |
| G2 Lakehouse | Continuing under the existing **$15** authorization. At most 720 scans at a 64 MiB cutoff would add about $0.242 to G2 for a future 20-run cloud test at $5/TB. Confirm remaining allowance at that time. | $15 existing |

[AWS Nova Micro rate examples](https://aws.amazon.com/blogs/machine-learning/cost-efficient-custom-text-to-sql-using-amazon-nova-micro-and-amazon-bedrock-on-demand-inference/)
[AgentCore pricing](https://aws.amazon.com/bedrock/agentcore/pricing/)
[ECR pricing](https://aws.amazon.com/ecr/pricing/)
[CloudWatch pricing](https://aws.amazon.com/cloudwatch/pricing/)
[S3 pricing](https://aws.amazon.com/s3/pricing/)
[Athena pricing](https://aws.amazon.com/athena/pricing/)

## G5 preparation

The strict TypeScript SSE consumer and filter reducer are usable by a browser
UI. The consumer validates the generated JSON Schema, SSE frame limits,
event order, snapshot and investigation identity. The reducer checks the
filter revision before applying proposed visualization updates. The
verification includes a real HTTP stream from the pinned DuckDB capture.
The G5 dashboard uses these modules in Nuxt 4. See the
[production-build and browser evidence](../STATUS.md).

## Authorized runtime deployment and verification

The approved `aegis-dev-identity` and `aegis-dev-agent` stacks use the
configured AWS profile and regional account. The identity stack provides
an invitation-only Cognito user pool, browser client and workspace group.
The runtime JWT authorizer binds the Cognito client. Application
validation checks the issuer, token expiration, token type, client ID,
workspace group and authenticated subject. The browser uses Authorization
Code with S256 PKCE on the registered loopback callback. Credentials stay
in memory while the browser is connected.

```sh
make synth-agent
make deploy-agent
make audit-agent
```

`deploy-agent` reviews project-owned CloudFormation change sets, verifies
the pinned Iceberg release and existing bootstrap, and publishes only the
AgentCore image to the project ECR repository. It checks the two inference
allocations against the shared $5 Bedrock ceiling. The $5 AgentCore ceiling
and the existing $15 lakehouse limit are checked separately before writes.
Deployed checkpoints use the existing project KMS key. Logs have seven-day
retention. Each runtime session has a 60-second idle and 120-second
lifetime ceiling. Validation uses a separate cap of 20 admitted attempts.

The [execution record](../STATUS.md) captures the regional resource
checks, real Cognito token validation, same-workspace user isolation,
cross-session SSE replay, active cancellation, latency and measured model
tokens. The development tests used temporary invited identities and
disabled them after verification. Frontend and standalone API hosting
remain separate from the approved runtime work.

## Snapshot-bound mitigation

The CVE card sends its exact `snapshot_id`, singleton `filters.cve_ids`,
preserved country filters and a `mitigation` object with `cve_id` and
evidence IDs from the authenticated card. The same graph resolves those
references through the official MCP transport. An archived CISA required
action is emitted as a cited claim after validation, visibly separate from
availability and asset applicability. No new model route accepts raw advisory
text or external instructions. The SOC/CSIRT draft stays in the operator's
browser. The next AgentCore revision needs read access to the one pinned
`snapshots/<release>/raw/00-cisa.json` object. The existing deployed runtime
remains on its verified baseline.

Component timing logs correlate by investigation trace ID. DuckDB/Athena
read timings sit inside the MCP timing, while checkpoint updates and model
selection have their own spans. Browser-to-first-event and full stream timing
remain end-to-end measurements. Concurrent spans may overlap.

## Final runtime revision

The final deployment updates the existing runtime in place. It reads the one
pinned CISA archive object for mitigation and checks Cognito plus the encrypted
subject decision before allowing direct invocations and MCP reads. Active
streams recheck current authorization. The authorized runtime, checkpoint
bucket, release and model budget remain the same physical resources.
[Identity runbook](identity-management.md) · [Execution record](../STATUS.md)
