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
