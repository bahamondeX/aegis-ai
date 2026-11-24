# Geographic source register

Qualification reviewed 2026-11-24 UTC. Geographic context and CVE exposure
are separate datasets. The active validation release is
`4e13ca6b-c2e1-4407-88bc-c362da7dbacb`.

| Source | Scope, method and rights | Decision |
| --- | --- | --- |
| [CRTC Telecommunications Sector – CMR](https://open.canada.ca/data/en/dataset/bd41f23a-6dbc-45ee-9419-422153aff567) | [Open Government Licence – Canada](https://open.canada.ca/en/open-government-licence-canada). The regulator publishes the share of population with facilities-based mobile network coverage, based on its Facilities Survey. C-T5 names provinces and territories. | Enabled locally for network context. Use the 2021 percentage for at least one LTE network, in 13 provinces or territories and one national record. The archive was republished 2026-08-20. These are historical population percentages, with no inferred operator name, CVE, site, or geographic coverage area. |
| [OSIPTEL](https://www.datosabiertos.gob.pe/dataset/cobertura-de-servicio-m%C3%B3vil-por-empresa-operadora) | Operator-reported mobile service. The newer catalog includes locality, operator, reporting period and technology. Catalog metadata indicates an attribution license. | Catalog resource retrieval returned HTTP 403. No records staged. |
| [CIRAD mobile coverage compendium](https://doi.org/10.18167/DVN1/ZTKQIH) | Dataverse v1 metadata shows CC BY 4.0 and multiple underlying sources with distinct measurements. Some values measure subscriber experience or time on a network. | Metadata and source notes downloaded for review. Mixed measures and underlying reuse terms require per-series qualification before use. |
| [PeeringDB API](https://www.peeringdb.com/apidocs/) | Self-reported peering and facility records. [Published acceptable use](https://tools.peeringdb.com/aup) restricts reuse outside allowed purposes. | No permission for this projection verified. No records staged. |
| [NRO delegated statistics](https://www.nro.net/about/rirs/statistics/) | RIR country code identifies the [registry's allocation or assignment context](https://www.apnic.net/about-apnic/corporate-documents/documents/resource-guidelines/rir-statistics-exchange-format/). | Registration metadata is a distinct future layer. Rights and terms across RIRs require review. |
| [ITU DataHub](https://beta.datahub.itu.int/about/) | Country-level statistics with CC BY-NC-SA 3.0 IGO notice and third-party exceptions. | Product redistribution and per-series method remain unqualified. |
| [TeleGeography](https://www2.telegeography.com/submarine-cable-faqs-frequently-asked-questions) | Published submarine cable mapping. Image reuse terms and underlying data terms are separate. | No cable data reuse scope verified. |
| [Shadowserver](https://www.shadowserver.org/statistics/) | The [dashboard guide](https://dashboard.shadowserver.org/help/) distinguishes scan populations, findings and honeypot attempts. Aggregation methodology and attribution vary by report. The dashboard expressly prohibits scraping and reselling data. | Candidate for a permissioned, explicitly CVE-attributed aggregate feed. The public dashboard was reviewed for qualification only. No figures staged. |
| Authorized inventory and SOC incident records | Require workspace permission, confirmed measurement or incident, allowed precision, publication scope and traceable provenance. | No authorized records available. Private site verification and confirmed incident layers remain disabled. |
| Shodan Free and geo-IP enrichment | A capability check and product redistribution permission are prerequisites. Geo-IP enrichment requires an already authorized observation. | No additional requests or subscription. No CVE exposure data staged. |

## Reproduce the qualified context projection

Use the exact [CRTC English CSV archive](https://applications.crtc.gc.ca/OpenData/CASP/COMMUNICATION%20MONITORING%20REPORTS/Telecommunications%20Overview/English/data-mobile-and-broadband-availability.zip).
Store it under ignored evidence storage. Review a changed upstream archive as a
new source release before updating its pinned SHA-256. The [catalog API](https://open.canada.ca/data/api/3/action/package_show?id=bd41f23a-6dbc-45ee-9419-422153aff567) verified license ID `ca-ogl-lgo` and the exact ZIP resource. The archived ZIP is
36,416,314 bytes with SHA-256
`b2872530eaba8207a8cc26e76031490365f51cb21dc7456b2251ad5ad04dddfa`.

```sh
uv run --locked --no-sync python -m scripts.stage_network_context \
  --snapshot 4e13ca6b-c2e1-4407-88bc-c362da7dbacb \
  --archive data/evidence/continuation/crtc.zip \
  --retrieved 2026-11-24T04:52:35Z
```

The parser reads only C-T5 and emits a versioned, immutable companion and
digest under `data/network/<snapshot_id>/`. The companion stays outside the
canonical Iceberg tables. A release without the companion reports network
coverage unavailable. The network source publishes Canadian LTE population
coverage. Country shading identifies the reporting geography. Selecting a
province displays that province's value while retaining the country outline.
Natural Earth country outlines carry no provider or vulnerability inference.

## Final deployment scope

The final deployment retains the qualified Canadian CRTC historical LTE
population coverage companion from release `4e13ca6b-c2e1-4407-88bc-c362da7dbacb`.
Cloud publication uses the reviewed SHA-256
`59612187c96f7f0d53757891abe740a730238fed4fed7b756da8a9d9474f4ceb`.
No further geographic providers or datasets are in scope. Canada is the
qualified network-context geography. CVE geographic exposure is unavailable.
Private confirmed tenant sites and SOC incident views remain disabled.

The 24 November production rerun independently exercised Canada and Peru
through the hosted interface and API on this release. Canada returned the
qualified network context. Peru showed unavailable network context.
Both scopes reported unavailable CVE geographic exposure and emitted no
exposure observations. [Production evaluation](evaluation.md)

## V2 network source qualification

| Source | Basis and rights | Executed outcome |
| --- | --- | --- |
| [World Bank WDI indicator IT.CEL.SETS.P2](https://data.worldbank.org/indicator/IT.CEL.SETS.P2) | World Telecommunication/ICT Indicators Database, ITU, through World Bank WDI. The series is CC BY 4.0. The measure is mobile cellular subscriptions per 100 people. Multiple subscriptions per person can raise the rate above 100. | Two official API manifests verified on the 2026-11-11 source release. A versioned local country and economy dimension has 217 entries. Of 14,322 normalized economy/year rows, 10,594 have a value and 3,728 are null. 214 economies have a historical value and 151 have values in 2024. No provider value was synthesized. |
| [NRO extended delegated statistics](https://www.nro.net/about/rirs/statistics/) | Daily registration reports from all five RIRs. Geography describes the country code in the registration record. The NRO describes the file as research and analysis data. Its linked format README returned 404 in this review. | The 2026-11-23 checksum-verified report contained 776,338 rows, including 117,801 ASN rows. The local audit projected 103,542 reported registration rows to 363 groups across 240 published registration country codes. Public redistribution scope requires separate verification. |
| [Shodan API](https://developer.shodan.io/api) | The documented count endpoint returns aggregates without using query credits. Metadata on filters and facets does not establish entitlement to each observation. The provider's [terms](https://static.shodan.io/legal/terms.html) require review for public redistribution. | The configured key returned plan `oss`, zero query and scan credits, 94 filters and 90 facets. Both lists include country, ASN, product and vulnerability fields. The existing free-plan guard did not confirm this plan. No CVE aggregate request or exposure publication was made. |

World Bank's country endpoint reports regions and country codes for both
economies and aggregates. The local projection excludes 2,904 aggregate rows
and reports 330 source rows whose economy code did not match the dimension.
All input rows remain in the archived source. The annual subscription metric
is independent of Canadian LTE population coverage and CVE geography.
[World Bank API documentation](https://datahelpdesk.worldbank.org/knowledgebase/articles/889392)

The NRO Parquet projection retains only country-code, registry and state
aggregates. The receipt binds them to the official report checksum.
Registration codes may include provider-specific values. The counts
measure reported registration ranges, and operational geography requires
independent evidence.

```sh
uv run --locked --no-sync python -m pipelines.wdi_context
uv run --locked --no-sync python -m pipelines.network_registry
```
