import type {
  Edge, Evidence, Exposure, Filters, InvestigationEvent, Report, RiskSummary,
} from '../../investigations/events'
import { readInvestigation } from '../../investigations/stream'
import {
  acceptProposal, begin, editFilters, receive, type InvestigationView,
} from '../../investigations/view'

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

type Coverage = Report['coverage'][number]

interface Envelope<T> {
  snapshot_id: string
  score_date: string
  coverage: Coverage[]
  availability: 'available' | 'unavailable'
  data: T
}

interface SnapshotData {
  coverage: Coverage[]
  kpis: Envelope<RiskSummary>
  cves: Vulnerability[]
  graph: Edge[]
  geo: Envelope<Exposure[]>
}

const initialFilters: Filters = { kev_only: true, limit: 60 }
const labels = {
  plan: 'Validate scope',
  research: 'Retrieve evidence',
  analyze: 'Rank and analyze',
  validate: 'Verify claims',
}

export function useDashboard() {
  const auth = useOperatorAuth()
  const status = ref<'idle' | 'loading' | 'ready' | 'error'>('idle')
  const error = ref('')
  const data = shallowRef<SnapshotData>()
  const scoreDate = ref('')
  const view = shallowRef<InvestigationView>({
    generation: 0, snapshot: '', seq: 0, terminal: false,
    manualRevision: 0, startedAtRevision: 0, filters: initialFilters,
  })
  const evidenceIndex = shallowRef<Record<string, Evidence>>({})
  const selectedEvidence = shallowRef<Evidence>()
  const events = shallowRef<InvestigationEvent[]>([])
  const report = shallowRef<Report>()
  const running = ref(false)
  const investigationError = ref('')
  const proposalHistory = shallowRef<{ id: string; sequence: number }[]>([])
  let dataRequest: AbortController | undefined
  let investigation: AbortController | undefined
  let requestKey = ''

  const filters = computed(() => view.value.filters)
  const steps = computed(() => events.value.flatMap((event) => {
    if (event.type !== 'node.started') return []
    return [{ id: event.seq, label: labels[event.payload.node], revision: event.payload.revision }]
  }))

  async function request<T>(path: string, signal?: AbortSignal, query = ''): Promise<T> {
    const response = await fetch('/api/aegis/' + path + query, {
      headers: { Authorization: 'Bearer ' + auth.token.value },
      signal, cache: 'no-store',
    })
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        throw new Error('Access expired or outside this workspace. Sign in again.')
      }
      throw new Error('The selected snapshot could not be read.')
    }
    return await response.json() as T
  }

  async function load() {
    const token = auth.token.value
    dataRequest?.abort()
    if (!token) {
      data.value = undefined
      status.value = 'idle'
      return
    }
    const controller = new AbortController()
    dataRequest = controller
    status.value = 'loading'
    error.value = ''
    const query = new URLSearchParams()
    for (const [key, value] of Object.entries(filters.value)) {
      for (const item of Array.isArray(value) ? value : [value]) {
        if (item !== null && item !== undefined) query.append(key, String(item))
      }
    }
    const suffix = '?' + query.toString()
    const signal = controller.signal
    try {
      const coverage = await request<Envelope<Coverage[]>>('v1/coverage', signal)
      const kpis = await request<Envelope<RiskSummary>>('v1/kpis', signal, suffix)
      const cves = await request<Envelope<Vulnerability[]>>('v1/cves', signal, suffix)
      const graphFilters = new URLSearchParams(query)
      if (cves.data.length) {
        graphFilters.delete('cve_ids')
        for (const row of cves.data.slice(0, 8)) graphFilters.append('cve_ids', row.cve_id)
      }
      const graph = await request<Envelope<Edge[]>>('v1/graph', signal, '?' + graphFilters)
      const geo = await request<Envelope<Exposure[]>>('v1/map', signal, suffix)
      if (signal.aborted || token !== auth.token.value) return
      if ([kpis, cves, graph, geo].some(item =>
        item.snapshot_id !== coverage.snapshot_id || item.score_date !== coverage.score_date,
      )) throw new Error('Data services disagree on the active snapshot.')
      if (view.value.snapshot && view.value.snapshot !== coverage.snapshot_id) {
        investigation?.abort()
        events.value = []
        report.value = undefined
        evidenceIndex.value = {}
        view.value = begin(view.value, coverage.snapshot_id)
      } else {
        view.value = { ...view.value, snapshot: coverage.snapshot_id }
      }
      scoreDate.value = coverage.score_date
      data.value = { coverage: coverage.data, kpis, cves: cves.data, graph: graph.data, geo }
      status.value = 'ready'
    } catch (failure) {
      if (signal.aborted) return
      data.value = undefined
      error.value = failure instanceof Error ? failure.message : 'The workspace could not be loaded.'
      status.value = 'error'
    }
  }

  async function changeFilters(next: Filters) {
    view.value = editFilters(view.value, next)
    await load()
  }

  async function start(question: string, scope?: 'global' | 'regional') {
    if (!question.trim() || running.value || !view.value.snapshot) return
    const controller = new AbortController()
    investigation = controller
    view.value = begin(view.value, view.value.snapshot)
    const generation = view.value.generation
    requestKey = crypto.randomUUID()
    events.value = []
    report.value = undefined
    running.value = true
    investigationError.value = ''
    try {
      const source = readInvestigation({
        endpoint: new URL('/api/aegis/v1/investigations', window.location.origin),
        token: auth.token.value,
        key: requestKey,
        signal: controller.signal,
        request: {
          question,
          snapshot_id: view.value.snapshot,
          filters: filters.value,
          scope: filters.value.country_iso2 ? 'regional' : scope,
        },
      })
      for await (const event of source) {
        const next = receive(view.value, generation, event)
        if (next === view.value) continue
        view.value = next
        events.value = [...events.value, event]
        if (event.type === 'evidence.added') {
          evidenceIndex.value = {
            ...evidenceIndex.value,
            ...Object.fromEntries(event.payload.items.map(item => [item.evidence_id, item])),
          }
        }
        if (event.type === 'report.completed') report.value = event.payload
        if (event.type === 'error') investigationError.value = event.payload.message
      }
    } catch (failure) {
      if (!controller.signal.aborted) {
        investigationError.value = failure instanceof Error
          ? failure.message : 'Investigation stream failed.'
      }
    } finally {
      if (investigation === controller) running.value = false
    }
  }

  async function cancel() {
    const id = view.value.investigation
    if (!id) {
      investigation?.abort()
      return
    }
    try {
      const response = await fetch(`/api/aegis/v1/investigations/${id}/cancel`, {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + auth.token.value, 'Idempotency-Key': requestKey },
      })
      if (!response.ok) throw new Error()
    } catch {
      investigation?.abort()
      investigationError.value = 'The connection closed before cancellation was acknowledged.'
    }
  }

  async function applyProposal() {
    const next = acceptProposal(view.value)
    if (next === view.value || !next.investigation) return
    proposalHistory.value = [...proposalHistory.value, {
      id: next.investigation,
      sequence: view.value.seq,
    }]
    view.value = next
    await load()
  }

  async function inspect(id: string) {
    if (evidenceIndex.value[id]) {
      selectedEvidence.value = evidenceIndex.value[id]
      return
    }
    try {
      const evidence = await request<Envelope<Evidence>>('v1/evidence/' + id)
      if (evidence.snapshot_id !== view.value.snapshot) throw new Error('Evidence snapshot changed.')
      evidenceIndex.value = { ...evidenceIndex.value, [id]: evidence.data }
      selectedEvidence.value = evidence.data
    } catch {
      error.value = 'Evidence could not be read from the active snapshot.'
    }
  }

  watch(auth.token, () => {
    investigation?.abort()
    view.value = begin(view.value, '')
    events.value = []
    report.value = undefined
    evidenceIndex.value = {}
    selectedEvidence.value = undefined
    void load()
  }, { immediate: true })
  onScopeDispose(() => {
    dataRequest?.abort()
    investigation?.abort()
  })

  return {
    status, error, data, scoreDate, view, filters, events, report, running, steps,
    investigationError, evidenceIndex, selectedEvidence, proposalHistory,
    load, changeFilters, start, cancel, applyProposal, inspect,
  }
}
