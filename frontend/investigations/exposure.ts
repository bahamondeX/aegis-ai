export interface ShadowserverContext {
  source: 'shadowserver'
  observation_id: string
  area: { country_iso2: string }
  coverage: 'partial'
  window_start: string
  window_end: string
  publication_date: string
  unit: 'vulnerable instances' | 'likely vulnerable instances' | 'unpatched instances'
  count: number | null
}

export type Metric = 'count' | 'severity'
export type Position = [number, number]
export type Severity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export interface Observation {
  context: ShadowserverContext
  distinct_cves: number
  max_cvss: number | null
  severity: Severity | null
}

export interface ExposureProjection {
  version: 1
  state: 'available' | 'unavailable'
  reason: 'no_source' | 'incompatible_window' | 'unsupported_filters' | null
  observations: Observation[]
}

export interface ExposurePage {
  version: 1
  context: ShadowserverContext
  rows: {
    cve_id: string
    cvss_score: number | null
    cvss_version: string | null
    cvss_source: string | null
    severity: Severity | null
  }[]
  next_cursor: string | null
}

export const NO_DATA = '#23323e'
export const UNRATED = '#776e90'

export const countRanges = [
  { minimum: 1, label: '1–4', color: '#a16b26' },
  { minimum: 5, label: '5–19', color: '#c38433' },
  { minimum: 20, label: '20+', color: '#e8aa55' },
]
export const severityRanges = [
  { minimum: 0, label: '0.0', color: '#5d8591' },
  { minimum: 0.1, label: '0.1–3.9', color: '#91803a' },
  { minimum: 4, label: '4.0–6.9', color: '#bb702c' },
  { minimum: 7, label: '7.0–8.9', color: '#d05a46' },
  { minimum: 9, label: '9.0–10.0', color: '#f36e90' },
]

export function areaColor(observation: Observation | undefined, metric: Metric): string {
  if (!observation) return NO_DATA
  const score = metric === 'severity' ? observation.max_cvss : observation.distinct_cves
  if (score === null) return UNRATED
  const ranges = metric === 'severity' ? severityRanges : countRanges
  return ranges.reduce((color, range) => score >= range.minimum ? range.color : color, NO_DATA)
}
