import type { Edge, Evidence, Exposure, Report } from './events.js'

export interface Vulnerability {
  cve_id: string
  description: string
  kev: boolean
  kev_added_at: string
  severity: string | null
  cvss_score: number | null
  cvss_version: string | null
  cvss_source: string | null
  epss: number | null
  percentile: number | null
  score_date: string | null
  source_refs: string[]
  epss_evidence_id: string | null
}

export interface NetworkRecord {
  record_id: string
  kind: 'operational_presence' | 'published_coverage' | 'registration_country'
  operator: string | null
  country_iso2: string
  region: string | null
  scope: string
  publication: string
  publisher: string
  license: string
  source_date: string
  reporting_year: number | null
  population_coverage: number | null
}

export interface GeographyCoverage {
  state: 'unavailable' | 'measured_zero' | 'observed'
  category: 'observed_exposure' | 'sensor_attempt' | 'confirmed_incident'
  country_iso2: string | null
  reason: string | null
  count: number | null
  unit: string | null
  precision: 'country' | 'region' | null
  window_start: string | null
  window_end: string | null
}

export interface MapProjection {
  geography_version: 1
  network: { state: 'available' | 'unavailable'; records: NetworkRecord[]; note: string }
  exposure: GeographyCoverage
}

export interface CveDetail {
  snapshot_id: string
  vulnerability: Vulnerability
  products: Edge[]
  applicability: {
    vendor: string; product: string; version: string | null
    start_including: string | null; start_excluding: string | null
    end_including: string | null; end_excluding: string | null; configuration_path: string
    evidence_id: string
  }[]
  evidence: Evidence[]
  geography: GeographyCoverage
  observations: Exposure[]
  mitigation: { text: string; evidence_id: string; source: 'cisa' } | null
}

export interface MitigationContext {
  cve_id: string
  evidence_ids: string[]
}

export function handoffSummary(cve: string, report: Report, country?: string | null) {
  const findings = report.claims.filter(claim => claim.key.startsWith(cve + '/'))
  return [
    'SOC / CSIRT review request',
    cve + ' · Snapshot ' + report.snapshot_id + (country ? ' · Scope ' + country : ''),
    ...findings.map(claim => claim.text + '\nEvidence: ' + claim.evidence_ids.join(', ')),
    report.geographic_note,
    'Asset, version, and incident status require confirmation.',
    'Requested action: verify applicability in authorized inventory and confirm remediation.',
  ].join('\n\n')
}
