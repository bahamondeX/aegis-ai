# V2 cost proposal

Model date 2026-11-24. All estimates use on-demand US East (N. Virginia)
rates and the workload assumptions below. Actual V2 AWS usage and billed
cost were unavailable. The existing MVP ceilings remain independent.

## Measured inputs

- The verified migration inventory contains 572 unique objects and
  1,926,772,199 bytes. This includes the verified KEV revision bodies.
- The pinned archive manifest lists 2,041 available EPSS days. Verified source
  artifacts cover 43 of them, leaving 1,998 for the proposed cloud backfill.
  The measured historical estimate is 7.20 GB for EPSS raw and normalized data.
- The NVD CPE Dictionary and CPE Match META files advertise about 0.98 GB
  compressed and 4.86 GB uncompressed in total. CPE normalization and churn
  are unmeasured. The storage scenarios include a 2 GB initial CPE normalized
  allowance and spare room for Silver, Gold, staging, results and retention.
- The local EPSS canary normalized 410,485 records in one daily file. Wall
  time was 3.12 s and process maximum resident memory was 225,476,608 bytes.
  The ARM64 Lambda proposal reserves 1 GiB of memory, 2 GiB of scratch,
  120 s per attempt and one concurrent invocation. Those are engineering
  bounds. Cloud timings remain to be measured.

## Rate basis

AWS regional public price files published between November 8 and 23 gave
these gross rates before free tiers, discounts and taxes.

| Meter | Rate |
| --- | ---: |
| S3 Standard | $0.023 per GB-month |
| S3 data or control PUT | $0.005 per 1,000 |
| S3 GET or HEAD planning tier | $0.0004 per 1,000 |
| S3 LIST planning tier | Included with PUT in the allocations below |
| KMS symmetric requests | $0.03 per 10,000 |
| Lambda Arm compute and requests | $0.0000133334 per GB-second and $0.20 per million requests |
| Lambda scratch above 512 MB | $0.0000000309 per GB-second |
| Athena SQL | $5 per TB scanned, with per-query rounding and minimum billing |
| Glue standard ETL or compaction allowance | $0.44 per DPU-hour |
| Public API and CloudWatch Logs ingestion | $3.50 per million REST requests and $0.50 per GB |

Use the existing KMS key, catalog and bootstrap. The modeled catalog request
and object counts fit the published first-million allowances, subject to
account-wide usage. The model includes KMS request charging before potential
S3 Bucket Key savings. Image storage and log retention overages have a
small separate allowance. [S3](https://aws.amazon.com/s3/pricing/) ·
[KMS](https://aws.amazon.com/kms/pricing/) · [Lambda](https://aws.amazon.com/lambda/pricing/) ·
[Athena](https://aws.amazon.com/athena/pricing/) · [Glue](https://aws.amazon.com/glue/pricing/) ·
[API Gateway](https://aws.amazon.com/api-gateway/pricing/) · [CloudWatch](https://aws.amazon.com/cloudwatch/pricing/)

The hosting scenario uses North American pay-as-you-go overage rates of
$0.085 per GB and $0.01 per 10,000 HTTPS requests without crediting the
free tier. AgentCore is conservatively modeled using the higher published
v2 consumption rates of $0.1276 per vCPU-hour and $0.0169 per GB-hour.
The Nova Micro planning inputs are $0.035 and $0.14 per million input and
output tokens. Reconcile the live runtime generation and token rates at
authorization. [CloudFront](https://aws.amazon.com/cloudfront/pricing/pay-as-you-go/) ·
[AgentCore](https://aws.amazon.com/bedrock/agentcore/pricing/) ·
[Nova Micro example](https://aws.amazon.com/blogs/machine-learning/prompting-for-the-best-price-performance/)

## Requested scopes

| Workload | Model assumptions | Estimate | Proposed ceiling |
| --- | --- | ---: | ---: |
| Initial migration and manual EPSS canary | Reviewed 572-object inventory, one reviewed EPSS window up to 32 dates, one worker at a time, three reserved attempts per date, at most 25 GB of total pilot storage | Under $2.00 | **$2 one-time**, included in the next row |
| Full V2 migration and backfill | 1,998 remaining EPSS days at 3 × 120 seconds each, 25 GB for one month, 50K S3 PUT/LIST and 120K reads, 100K KMS requests, 1K Athena statements at 64 MiB, 4 Glue DPU-hours of explicitly authorized validation/compaction, 0.5 GB logs and image/retention reserve | **$13.24** | **$15 one-time total** |
| Monthly pilot | 25 GB, 10K Athena statements at a billed average of 32 MB, 4 Glue DPU-hours, 300 worker calls at 30 seconds, 10K S3 PUT/LIST, 80K reads, 35K KMS calls, 25K REST and CDN HTTPS requests, 3 GB CDN egress, 10 vCPU-hours and 40 GB-hours AgentCore, 2M Nova input and 0.5M output tokens | **About $7/month** | **$10/month**, separate from one-time scope |
| Growth sensitivity | 150 GB, 100K statements at 32 MB, 12 Glue DPU-hours, 300K REST calls, 600K HTTPS requests, 100 GB egress, 80 vCPU-hours and 320 GB-hours AgentCore, 20M Nova input and 5M output tokens | **About $55/month** | Scenario only |

The one-time calculation allocates $9.59 to Arm compute, $0.03 to
scratch, $0.58 to storage, $0.30 to S3 requests, $0.30 to KMS, $0.34 to
Athena, $1.76 to Glue, and $0.35 to logs and image/retention allowance.
The existing deployed endpoints and model receive zero usage in this scope.
CPE and oversized replacement-baseline execution require measured canaries
within the remaining headroom and an explicit approval of their job shape.
The pilot applies only after the expanded release is separately reviewed.

Athena uses at most the existing 67,108,864-byte workgroup cutoff. Maintain
a statement count and token allocation in addition to AWS budget alerts.
Budget alerts do not prevent charges. Stop after an agreed request, byte,
time or attempt allowance is consumed. Reconcile Cost Explorer, S3 usage,
Athena scanned bytes, Lambda duration, and AgentCore/Bedrock usage against
the V2 prefix and account at the end of each authorized tranche.

## Activation requirements

Bind approval to the exact account, region, configured local profile,
project, S3 inventory digest and named EPSS plan digest. Supply the maximum
objects, bytes, attempts and spending for each action. The initial worker
creates no schedules. Apply subsequent plans only after reviewing live
receipts, elapsed time, billed usage, and timeout or memory failures.
Provisioning or enabling new AWS resources requires the applicable approval
and a live change-set review.
