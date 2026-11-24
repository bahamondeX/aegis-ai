# AEGIS AI technical case study

AEGIS AI helps a vulnerability operator move from a known exploited CVE to
its source-backed mitigation guidance. The command center combines ranked
vulnerabilities, product and CWE relationships, coverage, and a cited report.
A pinned release gives each chart, evidence drawer and investigation the same
view of the sources.

## Reproducible intelligence

The Python and Polars pipeline captures CISA KEV, FIRST EPSS and a bounded NVD
enrichment set. It retains source dates, retrieval timestamps, checksums and
licenses. Normalized Parquet and DuckDB support local verification. AWS Glue
and Apache Iceberg publish versioned tables in encrypted S3, which Athena
engine 3 reads through an encrypted workgroup with a 64 MiB scan limit. The
release pointer moves after a successful commit so a partial ingest does not
alter an in-progress investigation. [Lakehouse runbook](lakehouse.md)

CISA documents known exploitation, EPSS estimates likelihood over 30 days,
and NVD provides attributed severity and configurations. The dashboard ranks
known exploited vulnerabilities first, followed by EPSS and reported CVSS.
The separate Canadian CRTC layer represents 2021 LTE population coverage.
CVE geography remains explicitly unavailable, and private site and incident
layers are disabled. [Source register](source-register.md)

## Bounded investigation and delivery

LangGraph runs four typed stages for planning, MCP research, analysis and
evidence validation. The runtime exposes a bounded tool catalog. Queries
accept typed filters and parameterized read shapes. The Nova Micro model in
Amazon Bedrock selects keys from a short list of vetted claims. The validator
matches those keys to retrieved facts and renders the text from the snapshot.
The mitigation handoff remains an editable operator draft.

AgentCore runs the ARM64 investigation service and owns encrypted,
subject-bound checkpoints. Ordered SSE exposes node progress, evidence and
the validated report. A replay cursor can resume a prior stream and a
separate action can cancel active work. A private S3 static origin and
CloudFront deliver the Nuxt workspace. API Gateway response streaming and a
FastAPI Lambda relay the investigation without moving AWS credentials into
the browser. [Architecture and hosting runbook](hosting.md)

## Identity and authorization

Cognito runs code flow with S256 PKCE for native and Google identities.
Verified registrants enter a pending state. A server-authorized administrator
applies an auditable decision. The API and AgentCore independently check
current directory and approval state and bind the operator to the workspace
and checkpoint owner. Suspension cuts off stale sessions. The initial
administrator must change the temporary password, verify the mailbox and
enroll an authenticator before privilege is enabled. [Identity runbook](identity-management.md)

## Measured results

| Measurement | Observed result |
| --- | --- |
| Deterministic evaluator | 22 supported of 22 claims over five claim-bearing reports. Two correct claim-free reports evaluated separately. |
| Live Nova Micro mitigation | 7 supported of 7 claims over two runs, 444 input and 100 output tokens. |
| Live model duration | 795 ms first and 466 ms repeat, with 1,059.22 and 730.10 ms total on the local HTTP boundary. |
| CVE detail query parity | Eight Athena queries, 5,488,587 bytes scanned, equal to the pinned DuckDB detail result. |
| Hosted mitigation | 4 supported of 4 claims, 222 input and 59 output tokens. First visible progress at 2,996.45 ms and report at 16,216.16 ms. |
| Hosted Chromium rerun | Three production browser cases passed in 2.3 minutes. The new live response grounded 4 of 4 claims and used 222 input and 59 output tokens. Visible progress arrived at 15,388.32 ms and the report at 27,393.39 ms. |
| Earlier remote AgentCore baseline | 958.26 ms to first event, 28,610.92 ms to completion. This baseline predates the hosted identity extension. |

The evaluation report records acceptance by environment, tests and cases still
requiring live operator validation. The cost models cover bounded usage and
the execution record distinguishes recorded usage from billing data.
[Evaluation](evaluation.md) · [Execution record](../STATUS.md)


Actual production captures are in the ignored evidence directories
`data/evidence/final/` and `data/evidence/production-acceptance/`.
Sign-in, pending approval, world map, relationships, CVE detail and
mitigation captures were collected from the assigned CloudFront URL.
