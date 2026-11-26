<script setup lang="ts">
import { ArrowLeft, ArrowRight, Database, Search, X } from '@lucide/vue'

interface CatalogItem {
  cve_id: string
  year: number
  earliest_publication: string | null
  latest_modification: string | null
  in_kev: boolean
  has_cvss: boolean
  has_cwe: boolean
  has_cpe: boolean
  has_ssvc: boolean
  sources: ('cve' | 'kev' | 'nvd')[]
}
interface CatalogPage {
  release_id: string
  year: number
  years: number[]
  records_in_year: number
  total_distinct_cves: number
  next_after: string | null
  data: CatalogItem[]
}

const emit = defineEmits<{ detail: [id: string] }>()
const profilesEnabled = useRuntimeConfig().public.profilesV2 === true
const auth = useOperatorAuth()
const page = shallowRef<CatalogPage>()
const selected = shallowRef<CatalogItem>()
const search = ref('')
const matches = ref('')
const year = ref<number>()
const cursors = ref<(string | null)[]>([])
const cursor = ref<string | null>(null)
const loading = ref(false)
const error = ref('')
const number = new Intl.NumberFormat('en-US')
const names = { cve: 'CVE Program', kev: 'CISA KEV', nvd: 'NIST NVD' }
const citation = {
  cve: (id: string) => 'https://www.cve.org/CVERecord?id=' + encodeURIComponent(id),
  nvd: (id: string) => 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(id),
  kev: () => 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
}
const flags = [ ['has_cvss', 'CVSS'], ['has_cwe', 'CWE'], ['has_cpe', 'CPE'], ['has_ssvc', 'SSVC'] ] as const
let request: AbortController | undefined

async function load() {
  request?.abort()
  if (!auth.authenticated.value || !auth.sessionIdentity.value) { page.value = undefined; return }
  const controller = new AbortController()
  request = controller
  selected.value = undefined
  loading.value = true
  error.value = ''
  const params = new URLSearchParams({ limit: '20' })
  if (matches.value) params.set('cve_id', matches.value)
  else if (year.value) params.set('year', String(year.value))
  if (cursor.value) params.set('after', cursor.value)
  try {
    const response = await fetch('/api/aegis/v2/catalog?' + params, {
      headers: auth.requestHeaders(), signal: controller.signal, cache: 'no-store',
    })
    if (!response.ok) throw new Error('The vulnerability catalog is unavailable.')
    const next = await response.json() as CatalogPage
    if (controller.signal.aborted) return
    if (!/^[a-f0-9]{64}$/.test(next.release_id) || !Array.isArray(next.data) || next.data.length > 20 ||
        (page.value && page.value.release_id !== next.release_id)) throw new Error('The catalog release could not be verified.')
    page.value = next
    year.value = next.year
  } catch (cause) {
    if (!controller.signal.aborted) error.value = cause instanceof Error ? cause.message : 'The vulnerability catalog is unavailable.'
  } finally {
    if (!controller.signal.aborted) loading.value = false
  }
}

function applySearch() {
  const id = search.value.trim().toUpperCase()
  if (id && !/^CVE-\d{4}-\d{4,24}$/.test(id)) { error.value = 'Enter a complete CVE identifier.'; return }
  matches.value = id
  cursor.value = null
  cursors.value = []
  void load()
}

function selectYear(event: Event) {
  year.value = Number((event.target as HTMLSelectElement).value)
  search.value = ''
  applySearch()
}

function next() {
  if (!page.value?.next_after) return
  cursors.value.push(cursor.value)
  cursor.value = page.value.next_after
  void load()
}

function previous() {
  if (!cursors.value.length) return
  cursor.value = cursors.value.pop() ?? null
  void load()
}
watch([auth.authenticated, auth.sessionIdentity], load, { immediate: true })
onUnmounted(() => request?.abort())
</script>

<template>
  <section id="catalog" class="panel catalog-panel" aria-labelledby="catalog-title">
    <header class="panel-header">
      <div class="panel-title"><span class="icon-tile"><Database :size="17" aria-hidden="true" /></span>
        <div><h2 id="catalog-title">Vulnerability catalog</h2><p v-if="page">{{ number.format(page.total_distinct_cves) }} distinct CVEs</p></div>
      </div>
    </header>
    <form class="catalog-filters" @submit.prevent="applySearch">
      <label>Catalog year<select :value="year ?? ''" @change="selectYear">
        <option v-for="item in page?.years ?? []" :key="item" :value="item">{{ item }}</option>
      </select></label>
      <label>CVE identifier<input v-model="search" placeholder="CVE-2024-3400"></label>
      <button type="submit" class="primary-action"><Search :size="15" aria-hidden="true" /> Search catalog</button>
    </form>
    <p v-if="error" class="catalog-status" role="alert">{{ error }}</p>
    <div class="table-scroll" :aria-busy="loading">
      <p v-if="loading" class="catalog-status" role="status">Loading the catalog</p>
      <p v-else-if="page && !page.data.length" class="catalog-status">No matching records in this release.</p>
      <table v-else-if="page">
        <thead><tr><th>CVE</th><th>Official sources</th><th>Reported enrichment</th><th>KEV</th></tr></thead>
        <tbody>
          <tr v-for="item in page.data" :key="item.cve_id">
            <td><button type="button" class="text-button" @click="selected = item">{{ item.cve_id }}</button></td>
            <td>{{ item.sources.map(source => names[source]).join(' · ') }}</td>
            <td>{{ flags.filter(([key]) => item[key]).map(([, name]) => name).join(' · ') || 'Unavailable' }}</td>
            <td>{{ item.in_kev ? 'Listed' : '—' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <aside v-if="selected" class="catalog-summary" aria-label="CVE source overview">
      <div><h3>{{ selected.cve_id }}</h3><button type="button" aria-label="Close source overview" @click="selected = undefined"><X :size="16" /></button></div>
      <dl>
        <dt>Earliest recorded publication</dt><dd>{{ selected.earliest_publication?.slice(0, 10) ?? 'Unavailable' }}</dd>
        <dt>Latest recorded modification</dt><dd>{{ selected.latest_modification?.slice(0, 10) ?? 'Unavailable' }}</dd>
        <dt>Reported by</dt><dd><a v-for="source in selected.sources" :key="source" :href="citation[source](selected.cve_id)" target="_blank" rel="noopener noreferrer">{{ names[source] }}</a></dd>
      </dl>
      <button v-if="profilesEnabled" class="text-button" type="button" @click="emit('detail', selected.cve_id)">Open source profile</button>
    </aside>
    <footer v-if="page" class="catalog-pagination">
      <span>{{ number.format(page.records_in_year) }} CVEs dated {{ page.year }}</span>
      <div class="map-buttons">
        <button type="button" aria-label="Previous catalog page" :disabled="loading || !cursors.length" @click="previous"><ArrowLeft :size="16" /></button>
        <button type="button" aria-label="Next catalog page" :disabled="loading || !page.next_after" @click="next"><ArrowRight :size="16" /></button>
      </div>
    </footer>
  </section>
</template>

<style scoped>
.catalog-panel { margin-top: 16px; }
.catalog-filters, .catalog-pagination, .catalog-summary { display: flex; flex-wrap: wrap; align-items: end; gap: 10px; padding: 12px 14px; }
.catalog-filters label { display: grid; gap: 4px; color: var(--muted); font-size: 12px; }
.catalog-filters input, .catalog-filters select { padding: 5px 8px; border: 1px solid #344c60; border-radius: 4px; background: #0d1720; color: #e6f0f6; }
.catalog-pagination { justify-content: space-between; align-items: center; color: var(--muted); font-size: 12px; }
.catalog-status { padding: 8px 14px; color: var(--muted); }
.catalog-summary { display: block; border-top: 1px solid #283745; background: #10202a; }
.catalog-summary > div { display: flex; justify-content: space-between; }
.catalog-summary dl { display: grid; grid-template-columns: minmax(100px, max-content) 1fr; gap: 5px 16px; margin: 8px 0 0; font-size: 12px; }
.catalog-summary a { margin-right: 12px; color: #86e3d4; }
</style>
