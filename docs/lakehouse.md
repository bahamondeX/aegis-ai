# G2 lakehouse runbook

`make bootstrap` installs the locked Python, testing and CDK dependencies. CDK uses the
Node pin in `.nvmrc` and the CLI version in `infra/operations.py`. The Lambda build uses
a pinned Amazon Linux 2023 base and the Linux ARM64 wheels selected from `uv.lock`.
It includes the signed ICU extension from DuckDB's core repository so the runtime can
open UTC data without fetching an extension. [DuckDB extension installation](https://duckdb.org/docs/stable/extensions/installing_extensions)

```sh
make preflight bootstrap
make lint typecheck
make verify-phase1 SNAPSHOT="$AEGIS_SNAPSHOT"
make synth
make diff-local
docker buildx build --platform linux/arm64 --provenance=false --sbom=false \
  --load -f infra/Dockerfile -t aegis-ingest:local .
```

`make synth` writes the cloud assembly to `data/cdk.out`. `make diff-local` compares it
with an empty template locally. `make diff` queries the configured AWS environment and
uses template comparison without creating a change set. The full G2 gate requires
AWS deployment, live Athena parity and a verified schedule.

## Authorized AWS run

Use an existing AWS profile with the explicitly confirmed account and region.
Record the approved values in the root `.env` using `.env.example` as a template.
Keep `.env` at mode 600. Project commands read these fields automatically and an
explicit process value takes precedence.

| Variable | Value |
|---|---|
| `AEGIS_AWS_ACCOUNT`, `AEGIS_AWS_REGION`, `AEGIS_AWS_PROFILE` | The approved account, region and local AWS credential profile |
| `AEGIS_PROJECT_PREFIX` | The approved unique prefix, default `aegis-dev` |
| `AEGIS_DEPLOY_APPROVAL` | The approved account, region and prefix joined with slashes |
| `AEGIS_BUDGET_USD` | The approved USD amount |
| `AEGIS_SCHEDULE_ENABLED` | `0` for the first deployment, `1` after the first manual ingest succeeds |
| `AEGIS_SNAPSHOT` | The verified local run UUID used for seeding and pinned verification |

Run `make aws-preflight`. It verifies STS, available Lambda concurrency and the CDK
bootstrap parameter. Deployment calls also check the stack ownership tags. Permission
to describe an environment establishes read access. Asset publishing and CloudFormation
execution require their own IAM grants. If the project bootstrap is absent, run
`make prepare-bootstrap-policy`, record the approved project policy ARN in
`AEGIS_CDK_EXECUTION_POLICY_ARN`, and run `make cdk-bootstrap`. This uses the project's
bootstrap stack and qualifier. The execution policy limits KMS creation by project
tag and the account-level log-group and alias listing actions by region.

```sh
make synth
make diff
make deploy
make init-tables
make init-tables
# Optional source credentials from the mode-600 .env or process environment.
make secrets-sync
make publish-local
make publish-local
make ingest-cloud
# Set AEGIS_SCHEDULE_ENABLED=1 in the root .env before these commands.
make diff
make deploy
make verify-cloud
make verify-cloud LATEST=1
```

Set `AEGIS_SNAPSHOT` to the verified local run UUID before running these commands.
The two seed publishes must return identical run and Iceberg snapshot IDs. The manual
ingest must return a later capture ID with real feed coverage. Pinned verification
uses the original local snapshot when present. Verification of a new cloud capture
downloads its immutable Parquet and raw evidence, rebuilds DuckDB, and compares
canonical counts and grain uniqueness plus six query cases against Athena. Save
the operation logs and Athena query metrics as evidence. Capture resource IDs with
account identifiers sanitized.

S3 uses private, versioned, KMS-encrypted buckets with TLS-only policies. The query
workgroup requires engine 3 and KMS encryption and cancels queries above its
configured 64 MiB scanned-byte cutoff. Query result files and logs have seven-day
retention. SQL uses bounded, validated filters and generated Iceberg version IDs.
Cloud timestamp fields are floored to milliseconds for Athena, while the original
raw and Parquet values retain microseconds. [Athena Iceberg constraints](https://docs.aws.amazon.com/athena/latest/ug/querying-iceberg.html)

The six-hour EventBridge schedule invokes a single-concurrency Linux ARM64 Lambda.
The worker reuses the UTC day's EPSS capture when available, preserving the original
source date and retrieval timestamp. NVD enrichment remains limited to 20 KEV CVEs
per run. EPSS retains one identity partition per score date and changes only new or
revised partitions. Dimensions, bridges and other canonical tables represent the
current release. Glue uses Iceberg's optimistic locking. Readers resolve the S3
release pointer once and use the recorded Iceberg version of each table. If a write
fails before the pointer advances, readers can still use the previous release and the
next invocation can complete the release without duplicating facts.
[Iceberg version travel](https://docs.aws.amazon.com/athena/latest/ug/querying-iceberg-table-data.html)

The Lambda currently hydrates prior archives in its 2 GiB temporary workspace for
validation and carries a nine-minute timeout. Execution time and temporary space grow
with retained feed history. Measure both on the authorized deployment before using
the schedule over a long retention window. The 64 MiB query budget can also limit
full-history grain verification as the lake grows.

## Cost and teardown

Illustrative N. Virginia estimate before discounts and taxes is **$3.91/month**.
Assumptions are 120 Lambda invocations of one minute at 2 GiB, 200 Athena queries
scanning up to 64 MiB each, 2 GB of S3 storage, 3,000 S3 writes, 20,000 S3 reads,
1 GB of ECR storage, 100 MB of CloudWatch Logs, eight billable metrics and 10,000
KMS requests. With the same assumptions and all 120 invocations at the 540-second
timeout, the estimate is **$5.45/month**. Scheduler and Glue usage in this scenario
assumes the published free allowances are available. Actual usage, regional prices,
retained versions and additional workloads affect billing. The approved amount is
an authorization ceiling and billing still depends on usage.
[Athena](https://aws.amazon.com/athena/pricing/) ·
[Lambda](https://aws.amazon.com/lambda/pricing/) ·
[S3](https://aws.amazon.com/s3/pricing/) ·
[ECR](https://aws.amazon.com/ecr/pricing/) ·
[CloudWatch](https://aws.amazon.com/cloudwatch/pricing/) ·
[KMS](https://aws.amazon.com/kms/pricing/) ·
[EventBridge](https://aws.amazon.com/eventbridge/pricing/) ·
[Glue](https://aws.amazon.com/glue/pricing/)

With separate explicit teardown authorization, set `AEGIS_DESTROY_APPROVAL` in
`.env` to the project stack name and run `make destroy`. It removes the project's compute,
schedule and workgroup and retains the encrypted buckets, TLS policies, KMS key,
and Glue database. The SecureStrings and dedicated bootstrap resources are outside
the project stack. Record retained IDs before teardown. Retained resources can
continue to incur charges. Purging data, secrets or bootstrap resources requires
separate authorization because it can permanently remove evidence or affect other
stacks.
