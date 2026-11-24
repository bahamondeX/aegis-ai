# V2 time-series contract

The current canary builds an isolated Iceberg component from the exact
EPSS revisions referenced by a reviewed Bronze plan. The CLI reads a
single CVE from the manifest's Iceberg snapshot and returns the date
interval, daily unit, source evidence reference and observations.

```sh
uv run --locked --no-sync python -m pipelines.v2_history \
  --local-store data/v2-cloud-canary --warehouse data/v2-silver-canary \
  history --component <component-digest> --cve CVE-1999-0001 \
  --start 2026-06-14 --end 2026-06-16
```

Dates inside the pinned interval have one of three statuses.

| Status | Meaning |
| --- | --- |
| `observed` | The source supplies a score for that CVE and day. A score of zero is an observed probability. A missing source percentile remains null. |
| `cve_unscored` | The dated file exists and the CVE has no observation in it. |
| `source_absent` | The pinned official archive plan records the calendar date as absent. Pending listed dates block publication of the component. |

Daily, seven-day and 30-day differences require an observation on both
endpoint dates under the same model. Seven-day and 30-day rolling means
and population standard deviations require a complete run of consecutive
daily observations under one model. Query reads may include up to 30 days
of preceding context within the published component. The response still
starts on the requested date. A model transition is marked when adjacent
observed dates use different versions. The canary holds 32 calendar days
per plan.

The command center timeline contract retains source granularity. EPSS is
daily. WDI is annual and CRTC is a separately dated population coverage
measurement. A year-level source is displayed with its actual reporting
period. Missing intervals remain explicit. Current geographic values cannot
be used to fill past frames. Browser playback, brushing, comparisons and
release-aware caching are pending the combined analytical release.
