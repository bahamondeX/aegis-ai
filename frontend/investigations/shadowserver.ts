import type { ExposurePage, ExposureProjection, Observation, Severity, ShadowserverContext } from './exposure.js'
import catalog from './shadowserver-catalog.json' with { type: 'json' }

export const shadowserver = {
  label: 'Fuente: The Shadowserver Foundation',
  href: 'https://www.shadowserver.org/news/shadowserver-2025-highlights-of-the-year-in-review/',
  published: '2026-09-07',
}

interface ScanSummary {
  day: string
  cve: keyof typeof catalog
  unit: ShadowserverContext['unit']
  countries: ReadonlyArray<{ code: string; count: number | null }>
}

// Transcription of explicitly named countries from the official annual review.
const summaries: ScanSummary[] = [
  { day: '2025-07-20', cve: 'CVE-2025-54309', unit: 'unpatched instances', countries: [
    { code: 'US', count: null }, { code: 'DE', count: null }, { code: 'CA', count: null },
  ] },
  { day: '2025-01-16', cve: 'CVE-2024-12084', unit: 'vulnerable instances', countries: [
    { code: 'US', count: 5_000 },
  ] },
  { day: '2025-01-09', cve: 'CVE-2025-0282', unit: 'likely vulnerable instances', countries: [
    { code: 'US', count: null }, { code: 'FR', count: null }, { code: 'ES', count: null },
  ] },
]
export const demoDates = summaries.map(summary => summary.day)
export const demoCves = Object.keys(catalog).sort()

export interface DemoCve {
  id: string
  product: string
  description: string
  cvss_score: number | null
  cvss_version: string | null
  cvss_source: string | null
  severity: Severity | null
  source_url: string
}

export function demoCve(id: string): DemoCve | undefined {
  if (!Object.hasOwn(catalog, id)) return undefined
  const row = catalog[id as keyof typeof catalog]
  return { ...row, id, severity: row.severity as Severity | null }
}

export function demoProjection(day: string, cve: string): ExposureProjection {
  const observations: Observation[] = summaries.flatMap(summary => {
    if (summary.day !== day || (cve && summary.cve !== cve)) return []
    const detail = demoCve(summary.cve)
    return summary.countries.map(({ code, count }) => ({
      context: {
        source: 'shadowserver',
        observation_id: [summary.day, code, summary.cve].join('/'),
        area: { country_iso2: code },
        coverage: 'partial',
        window_start: day,
        window_end: day,
        publication_date: shadowserver.published,
        unit: summary.unit,
        count,
      },
      distinct_cves: 1,
      max_cvss: detail?.cvss_score ?? null,
      severity: detail?.severity ?? null,
    }))
  })
  return {
    version: 1,
    state: observations.length ? 'available' : 'unavailable',
    reason: observations.length ? null : 'no_source',
    observations,
  }
}

export function demoArea(
  projection: ExposureProjection, context: ShadowserverContext,
): ExposurePage {
  if (!projection.observations.some(row => row.context.observation_id === context.observation_id)) {
    throw new Error('La observación ya no pertenece a la selección')
  }
  const cve = context.observation_id.split('/')[2] ?? ''
  const detail = demoCve(cve)
  if (!detail) throw new Error('La ficha no pertenece a la muestra')
  return { version: 1, context, rows: [{ ...detail, cve_id: cve }], next_cursor: null }
}
