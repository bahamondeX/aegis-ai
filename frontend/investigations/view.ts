import type { Analytics, FilterProposal, Filters, InvestigationEvent } from './events.js'

export interface InvestigationView {
  generation: number
  snapshot: string
  investigation?: string
  seq: number
  terminal: boolean
  manualRevision: number
  startedAtRevision: number
  filters: Filters
  proposal?: FilterProposal
  analytics?: Analytics
  proposedAnalytics?: Analytics
}

function filtersMatch(first: Filters, second: Filters): boolean {
  const normalize = (filters: Filters) => JSON.stringify([
    [...(filters.cve_ids ?? [])].sort(),
    filters.country_iso2 ?? null,
    filters.kev_only ?? false,
    filters.min_epss ?? null,
    filters.severity ?? null,
    filters.date_from ?? null,
    filters.date_to ?? null,
    filters.limit ?? 50,
  ])
  return normalize(first) === normalize(second)
}

export function begin(view: InvestigationView, snapshot: string): InvestigationView {
  return {
    generation: view.generation + 1,
    snapshot,
    seq: 0,
    terminal: false,
    manualRevision: view.manualRevision,
    startedAtRevision: view.manualRevision,
    filters: view.filters,
  }
}

export function editFilters(view: InvestigationView, filters: Filters): InvestigationView {
  return {
    ...view,
    filters,
    manualRevision: view.manualRevision + 1,
    proposal: undefined,
    analytics: undefined,
    proposedAnalytics: undefined,
  }
}

export function receive(
  view: InvestigationView,
  generation: number,
  event: InvestigationEvent,
): InvestigationView {
  if (generation !== view.generation || view.terminal || event.seq !== view.seq + 1) return view
  if (event.type === 'investigation.started') {
    if (view.seq !== 0 || event.payload.snapshot_id !== view.snapshot) return view
    return { ...view, seq: event.seq, investigation: event.investigation_id }
  }
  if (view.investigation !== event.investigation_id) return view
  if ('snapshot_id' in event.payload && event.payload.snapshot_id !== view.snapshot) return view
  const next = { ...view, seq: event.seq }
  if (event.type === 'done') return { ...next, terminal: true }
  if (view.manualRevision !== view.startedAtRevision) return next
  if (event.type === 'ui.filters.proposed') return { ...next, proposal: event.payload }
  if (event.type === 'analytics.updated') {
    if (filtersMatch(view.filters, event.payload.filters)) return { ...next, analytics: event.payload }
    if (view.proposal && filtersMatch(view.proposal.filters, event.payload.filters)) {
      return { ...next, proposedAnalytics: event.payload }
    }
  }
  return next
}

export function acceptProposal(view: InvestigationView): InvestigationView {
  if (!view.proposal || view.proposal.snapshot_id !== view.snapshot ||
      view.manualRevision !== view.startedAtRevision) return view
  const { filters } = view.proposal
  return {
    ...view,
    filters,
    proposal: undefined,
    analytics: view.proposedAnalytics ??
      (view.analytics && filtersMatch(filters, view.analytics.filters) ? view.analytics : undefined),
    proposedAnalytics: undefined,
  }
}
