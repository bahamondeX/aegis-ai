# Geographic evidence and CVE detail contract

The G5 extension preserves all eight canonical Iceberg tables and their
historical manifests. Country context is a separately dated, digest-bound
companion to a pinned release. Its read scope is country only and ignores CVE,
severity, ranking, and date filters. Country geometry comes from Natural Earth.
Registration, operator presence and published coverage have different labels.
A country outline never represents confirmed site coordinates.

The authenticated `GET /v1/map` response adds a `geography_version` and
separate `network` and `exposure` metadata. The existing observation list
and envelope stay compatible. Until a qualified public-safe aggregation policy
exists, the new exposure view serves an empty observation list with an
unavailable reason. Measured zero requires an explicit source value with
known coverage, unit and time window. Sensor attempts and confirmed
incidents are separate categories. They stay disabled with this release.
The public-safe projection has no raw hosts, ASNs, exact locations or
private incidents. All existing data routes still require authentication.

The authenticated `GET /v1/cves/{cve_id}` adds one snapshot-bound detail read.
It returns global vulnerability attributes, source-bound affected product
conditions and mitigation evidence, with optional country-scoped exposure
separate from those global facts. CVSS, EPSS and KEV keep their original
definitions. An NVD CPE condition identifies a published applicability
criterion. Asset version, environment and installation require separate
confirmation. Raw archive object names and identifiers are internal only.

The existing investigation POST accepts an optional typed mitigation context
containing the selected CVE and source evidence IDs. It requires an explicit
matching snapshot and the exact selected CVE in filters. The existing
`get_vulnerabilities` tool accepts an optional singleton detail flag for this
path. The six tool names, four graph nodes, SSE version and event kinds
are unchanged. The researcher revalidates supplied IDs against the actual
selected row before resolving evidence. It reads global CVE attributes
separately from country exposure and never proposes an implicit scope change.
Source instructions are shown as citations after validation and kept out of
the model prompt. A handoff is editable client-side and never transmitted.

Current deployed AgentCore and Cognito remain on their verified versions.
The extension operates locally. Future cloud execution requires an
explicitly reviewed deployment of code and read scope, including carefully
limited access to the pinned source archive. No immutable storage format
or AWS policy is changed by this increment.

## Companion data dictionary

| Field | Meaning |
| --- | --- |
| `snapshot_id`, `version` | Exact threat release and independent companion contract version |
| `record_id`, `checksum` | Stable projection record ID and source archive SHA-256 |
| `kind`, `operator` | Published coverage, operational presence or registration. Operator is nullable for regulator aggregates. |
| `country_iso2`, `region` | ISO country and optional source-named administrative area |
| `reporting_year`, `source_date`, `retrieved_at` | Measurement year, publication date and UTC capture time |
| `population_coverage`, `scope` | Unit fraction of the population and the regulator's coverage definition |
| `publication`, `publisher`, `license` | Source provenance and attribution |

The local CRTC capture contributes national and provincial context. Country
scope filters the API companion. A province filter narrows the source rows
within that same response. The map displays Natural Earth country geography.
The ratio is a 2021 population metric and carries no asset-level detail.
Consult the [source register](source-register.md) for the archived source and
reproduction command.

## Demo histórica de Shadowserver

La demo usa una transcripción puntual del resumen anual publicado por
The Shadowserver Foundation el 7 de septiembre de 2026. El artículo
identifica las siguientes ventanas de observación. Los tres días se
sirven por separado, con cobertura parcial. La fecha de publicación
permanece separada de la observación. [Resumen anual de Shadowserver](https://www.shadowserver.org/news/shadowserver-2025-highlights-of-the-year-in-review/)

| Día observado | CVE | Países citados | Unidad original | Recuento nacional publicado en la muestra |
| --- | --- | --- | --- | --- |
| 2025-01-09 | CVE-2025-0282 | US, FR, ES | likely vulnerable instances | Ausente |
| 2025-01-16 | CVE-2024-12084 | US | vulnerable instances | 5 000 en US |
| 2025-07-20 | CVE-2025-54309 | US, DE, CA | unpatched instances | Ausente |

Las celdas registran las observaciones nacionales explícitas de la
publicación. Quedan fuera los totales mundiales y las métricas
de ataques. Cada combinación no documentada de país, CVE y fecha
muestra «Sin datos». Las CVE distintas se cuentan dentro de la muestra
del día. Cada día contiene una sola CVE y solo una celda tiene un
recuento nacional publicado. La muestra no permite estimar una
correlación entre el número de CVE y el volumen de exposición.

La tarjeta lee las valoraciones de tres fichas oficiales de NVD capturadas
para la demo. NVD solo aporta atributos globales y se enlaza en la ficha
junto con el catálogo global autenticado de AEGIS. Shadowserver es la
única fuente geográfica. Se aplica la misma preferencia de versiones
CVSS y tipo de valoración del catálogo. [API de vulnerabilidades de NVD](https://nvd.nist.gov/developers/vulnerabilities)

El build completo de Nuxt para Vercel prerenderiza la ruta `/demo/exposure/` y reutiliza
el panel, coroplético, selectores y navegación del globo. El adaptador
local tiene un esquema de evidencia distinto del inventario privado.
El navegador no consulta Shadowserver, AWS ni `/v1/map` para servir la
muestra. La API privada y sus consumidores conservan los contratos
existentes. La página no incluye informes privados ni registros de
endpoints individuales.

Para una comparación cuantitativa hace falta un CSV o JSON agregado
oficial, o una muestra autorizada para publicar en Preview. Debe aportar
país ISO 3166-1, día UTC, CVE, grupo de medición, recuento, unidad,
precisión y cobertura, para varias CVE por país y fecha del mismo grupo.
La población y ventana deben ser comparables. El enlace público permite
consultar la investigación original. La política del dashboard restringe
la extracción automatizada y define la atribución y usos admitidos.
[Política de uso del dashboard](https://www.shadowserver.org/statistics/)

El workspace incluye el enlace **Exposición a CVE · Demo histórica**.
Se conserva la navegación al catálogo global en el mismo origen y las
rutas servidor de sesión e investigaciones. La atribución enlazada
usa texto. El logo de Shadowserver queda pendiente de autorización
escrita para su uso en AEGIS.
[Términos de Shadowserver](https://www.shadowserver.org/privacy-and-terms/)
