<script setup lang="ts">
import {
  Activity, ArrowUpRight, Bot, ChartNoAxesCombined, ChevronDown,
  CircleHelp, Database, Filter, Fingerprint, GitFork, Globe2, LayoutDashboard, LockKeyhole,
  LogOut, Menu, RefreshCw, ScanSearch, Shield, X,
} from '@lucide/vue'
import type { CveDetail } from '../../investigations/geography'
import type { HistorySelection } from '../../investigations/stream'
import type { Filters } from '../../investigations/events'

const auth = useOperatorAuth()
const profilesEnabled = useRuntimeConfig().public.profilesV2 === true
const historyYear = ref<number>()
const historyEnabled = useRuntimeConfig().public.epssHistoryV2 === true
const catalogEnabled = useRuntimeConfig().public.catalogV2 === true
const {
  status, error, data, scoreDate, view, filters, report, running, steps,
  investigationError, selectedEvidence, proposalHistory, load, changeFilters, start,
  cancel, applyProposal, inspect, detail, detailCveId, detailLoading, detailError,
  openDetail, closeDetail, mitigationCve, mitigationCountry,
} = useDashboard()

const access = ref('')
const loginError = ref('')
const menuOpen = ref(false)
const activeSection = ref('overview')
const filterPopover = ref(false)
const cveQuery = ref('')
const countryQuery = ref('')
const severityQuery = ref('')
const minEpss = ref('')
const dateFrom = ref('')
const dateTo = ref('')
const onlyKev = ref(true)
const numeric = new Intl.NumberFormat('en-US')
const proportion = new Intl.NumberFormat('en-US', { style: 'percent', maximumFractionDigits: 3 })
const sourceLabels = { cisa: 'CISA KEV', epss: 'FIRST EPSS', nvd: 'NIST NVD', shodan: 'Geographic exposure' }
const nav = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'exposure', label: 'Exposure map', icon: Globe2 },
  { id: 'relationships', label: 'Relationships', icon: GitFork },
  { id: 'investigations', label: 'Investigations', icon: Bot },
  ...(catalogEnabled ? [{ id: 'catalog', label: 'Vulnerability catalog', icon: ScanSearch }] : []),
  { id: 'sources', label: 'Sources', icon: Database },
]
const stats = computed(() => {
  const summary = data.value?.kpis
  const values = summary?.availability === 'available' ? summary.data : undefined
  return [
    { label: 'Vulnerabilities', value: values?.total_cves, context: 'In current scope', icon: ScanSearch, color: 'mint' },
    { label: 'Known exploited', value: values?.kev_cves, context: 'CISA KEV catalog', icon: Shield, color: 'orange' },
    { label: 'EPSS ≥ 0.50', value: values?.high_epss, context: 'FIRST 30-day probability', icon: Activity, color: 'blue' },
    { label: 'NVD enriched', value: values?.with_nvd, context: 'Source-reported details', icon: Fingerprint, color: 'purple' },
  ]
})
const displayedRows = computed(() => data.value?.cves.slice(0, 10) ?? [])
const activeChips = computed(() => {
  const current = filters.value
  return [
    ...(current.kev_only ? ['Known exploited'] : []),
    ...(current.country_iso2 ? [current.country_iso2] : []),
    ...(current.cve_ids ?? []),
    ...(current.severity ? [current.severity] : []),
    ...(current.min_epss === null || current.min_epss === undefined ? [] : [`EPSS ≥ ${current.min_epss}`]),
    ...(current.date_from ? [`From ${current.date_from}`] : []),
    ...(current.date_to ? [`Through ${current.date_to}`] : []),
  ]
})
const ready = computed(() => status.value === 'ready')
const isSignedIn = auth.authenticated
const hasSession = auth.signedIn
const account = auth.account
const profileOpen = ref(false)
onMounted(() => void auth.refreshAccount())
watch(filters, current => {
  cveQuery.value = (current.cve_ids ?? []).join(', ')
  countryQuery.value = current.country_iso2 ?? ''
  severityQuery.value = current.severity ?? ''
  minEpss.value = current.min_epss?.toString() ?? ''
  dateFrom.value = current.date_from ?? ''
  dateTo.value = current.date_to ?? ''
  onlyKev.value = current.kev_only ?? false
}, { immediate: true })

function handleLogin() {
  try {
    loginError.value = ''
    auth.acceptLocal(access.value.trim())
    access.value = ''
  } catch {
    loginError.value = 'Enter a valid development access token.'
  }
}
function navigate(id: string) {
  activeSection.value = id
  menuOpen.value = false
}
function filterCve(id: string) {
  void changeFilters({ ...filters.value, cve_ids: [id] })
}
async function mitigate(current: CveDetail) {
  closeDetail()
  navigate('investigations')
  await nextTick()
  document.getElementById('investigation-title')?.focus()
  void start('How to mitigate ' + current.vulnerability.cve_id + '?', 'global', current)
}
async function analyzeHistory(selection: HistorySelection) {
  navigate('investigations')
  await nextTick()
  document.getElementById('investigation-title')?.focus()
  void start('Summarize the selected global FIRST EPSS history', 'global', undefined, selection)
}
function inspectDetail(id: string) {
  closeDetail()
  void inspect(id)
}
function openCveEvidence(row: typeof displayedRows.value[number]) {
  if (row.source_refs[0]) void inspect(row.source_refs[0])
}
function submitFilters() {
  const next: Filters = {
    cve_ids: cveQuery.value.split(/[,\s]+/).filter(Boolean).map(cve => cve.toUpperCase()),
    country_iso2: countryQuery.value.trim().toUpperCase() || null,
    kev_only: onlyKev.value,
    min_epss: minEpss.value ? Number(minEpss.value) : null,
    severity: (severityQuery.value || null) as Filters['severity'],
    date_from: dateFrom.value || null,
    date_to: dateTo.value || null,
    limit: 60,
  }
  filterPopover.value = false
  void changeFilters(next)
}
const reset = () => { void changeFilters({ kev_only: true, limit: 60 }) }
</script>

<template>
  <div class="workspace">
    <a href="#overview" class="skip-link">Skip to content</a>
    <aside class="sidebar" :class="{ 'mobile-open': menuOpen }">
      <a href="#overview" class="brand" @click="navigate('overview')">
        <span class="brand-mark"><Shield :size="24" :stroke-width="2.1" aria-hidden="true" /><i /></span>
        <span><strong>AEGIS</strong><em>THREAT INTELLIGENCE</em></span>
      </a>
      <nav aria-label="Workspace navigation">
        <a
v-for="entry in nav" :key="entry.id" :href="'#' + entry.id"
           :aria-current="activeSection === entry.id ? 'location' : undefined"
           :class="{ active: activeSection === entry.id }" @click="navigate(entry.id)">
          <component :is="entry.icon" :size="19" aria-hidden="true" /> {{ entry.label }}
        </a>
      </nav>
      <div class="sidebar-footer">
        <div class="workspace-scope"><span class="status-dot" /><div><strong>AEGIS Workspace</strong><span>Development workspace</span></div></div>
        <button v-if="hasSession" class="sidebar-signout" type="button" @click="auth.signOut"><LogOut :size="15" /> Sign out</button>
      </div>
    </aside>

    <main id="overview" class="main-content">
      <div class="topbar">
        <div class="breadcrumbs">
          <button class="icon-button mobile-menu" type="button" aria-label="Open navigation" :aria-expanded="menuOpen" @click="menuOpen = !menuOpen">
            <X v-if="menuOpen" :size="21" /><Menu v-else :size="21" />
          </button>
          <span>Workspace</span><span class="slash">/</span><strong>Threat intelligence</strong>
        </div>
        <div class="top-actions">
          <button v-if="isSignedIn && account" type="button"
                  class="icon-button profile-trigger" aria-label="Open account profile" :aria-expanded="profileOpen"
                  @click="profileOpen = !profileOpen"><AccountAvatar :account="account" /></button>
          <span v-if="scoreDate" class="snapshot-pill" aria-label="Active snapshot">
            <Database :size="14" aria-hidden="true" /> <span>SNAPSHOT</span> {{ scoreDate }}
          </span>
          <button
v-if="isSignedIn" type="button" class="icon-button refresh" aria-label="Refresh snapshot" title="Refresh snapshot"
                  :disabled="status === 'loading'" @click="load"><RefreshCw :size="16" /></button>
        </div>
      </div>

      <div class="content">
        <section v-if="profileOpen && isSignedIn && account" class="panel account-profile" aria-label="Account profile">
          <AccountAvatar :account="account" />
          <div><h2>Account profile</h2><p>{{ account.email }}</p><p>{{ account.provider === 'Google' ? 'Google · Email verified' : 'Email · Authenticator verified' }}</p></div>
          <UButton variant="ghost" @click="profileOpen = false">Close</UButton>
        </section>
        <div class="page-heading">
          <div>
            <h1>Threat command center<span>.</span></h1>
            <p>Track known exploitation, inspect relationships and investigate evidence.</p>
          </div>
          <div v-if="isSignedIn" class="page-actions">
            <UButton class="primary-action" variant="solid" size="md" color="primary" to="#investigations"><Bot :size="17" /> Investigate</UButton>
          </div>
        </div>

        <section v-if="!isSignedIn" class="panel sign-in" aria-labelledby="sign-in-heading">
          <div class="icon-tile"><LockKeyhole :size="20" aria-hidden="true" /></div>
          <h2 id="sign-in-heading">Connect your workspace</h2>
          <p v-if="auth.loading.value">Checking workspace access…</p>
          <template v-else-if="auth.blocked.value">
            <p>Use Google with a verified email or verify both your email and authenticator for password sign-in.</p>
            <UButton variant="outline" @click="auth.signOut">Sign out</UButton>
          </template>
          <form v-else-if="auth.development" @submit.prevent="handleLogin">
            <label><span>Development access token</span>
              <input v-model="access" type="password" name="access" autocomplete="off" required>
            </label>
            <UButton type="submit" class="primary-action">Connect</UButton>
          </form>
          <UButton v-else class="primary-action" to="/login">Sign in</UButton>
          <p v-if="loginError || auth.error.value" class="form-error" role="alert">{{ loginError || auth.error.value }}</p>
        </section>

        <template v-else>
          <div class="scope-bar">
            <div class="scope-label"><Filter :size="16" aria-hidden="true" /><span>Active scope</span></div>
            <div class="scope-chips">
              <template v-for="chip in activeChips" :key="chip">
                <button
                  v-if="chip.startsWith('CVE-')" class="cve-scope-chip"
                  type="button" :aria-label="'Open CVE detail for ' + chip" @click="openDetail(chip)"
                >{{ chip }}</button>
                <span v-else>{{ chip }}</span>
              </template>
              <span v-if="!activeChips.length">All ranked vulnerabilities</span>
            </div>
            <button class="scope-toggle" type="button" :aria-expanded="filterPopover" @click="filterPopover = !filterPopover">Filters <ChevronDown :size="15" /></button>
            <button class="scope-reset" type="button" title="Reset to default scope" @click="reset">Reset</button>
          </div>
          <form v-if="filterPopover" class="panel filter-grid" @submit.prevent="submitFilters">
            <label>CVE IDs<input v-model="cveQuery" placeholder="Comma-separated CVE IDs"></label>
            <label>Country code<input v-model="countryQuery" placeholder="ISO alpha-2" maxlength="2" pattern="[A-Za-z]{2}"></label>
            <label>Severity<select v-model="severityQuery"><option value="">All</option><option v-for="tier in ['NONE','LOW','MEDIUM','HIGH','CRITICAL']" :key="tier">{{ tier }}</option></select></label>
            <label>Minimum EPSS<input v-model="minEpss" type="number" min="0" max="1" step="0.01" placeholder="0 through 1"></label>
            <label>KEV added from<input v-model="dateFrom" type="date"></label>
            <label>KEV added through<input v-model="dateTo" type="date"></label>
            <label class="check-control"><input v-model="onlyKev" type="checkbox"> Known exploited only</label>
            <UButton type="submit" class="primary-action">Apply filters</UButton>
          </form>
          <p v-if="error" class="panel load-error" role="alert">{{ error }} <button type="button" @click="load">Retry</button></p>
          <p v-if="status === 'loading'" class="sr-only" role="status">Loading active snapshot</p>
          <div class="kpi-grid" aria-label="Vulnerability metrics" :aria-busy="status === 'loading'">
            <article v-for="entry in stats" :key="entry.label" class="panel kpi-card" :class="entry.color">
              <div class="kpi-top"><span>{{ entry.label }}</span><span class="icon-tile"><component :is="entry.icon" :size="17" aria-hidden="true" /></span></div>
              <strong>{{ entry.value === undefined ? '—' : numeric.format(entry.value) }}</strong>
              <div class="kpi-caption">{{ entry.context }}</div>
            </article>
          </div>

          <div class="feature-grid">
            <ExposurePanel
              :projection="data?.geo" :observations="data?.geo.data ?? []" :active="ready"
              :history-year="historyYear" :country="filters.country_iso2 || undefined" @detail="openDetail"
              @country="country => changeFilters({ ...filters, country_iso2: country || null })" />
            <NetworkPanel :edges="data?.graph ?? []" @inspect="inspect" @filter="filterCve" @detail="openDetail" />
          </div>
          <EpssHistory v-if="historyEnabled && ready" @network-year="historyYear = $event" @investigate="analyzeHistory" />
          <CatalogPanel v-if="catalogEnabled && ready" @detail="openDetail" />
          <div class="review-grid">
            <div class="review-main">
              <AnalyticsPanel :rows="data?.cves ?? []" />
              <section class="panel cohort-panel" aria-labelledby="cohort-heading">
                <header class="panel-header">
                  <div class="panel-title"><span class="icon-tile"><ChartNoAxesCombined :size="18" /></span>
                    <div><h2 id="cohort-heading">Ranked vulnerabilities</h2><p>KEV priority, EPSS, then available CVSS</p></div>
                  </div>
                  <span v-if="ready" class="small-count">{{ displayedRows.length }} SHOWN</span>
                </header>
                <div class="table-scroll">
                  <table v-if="displayedRows.length">
                    <thead><tr><th>CVE</th><th>KEV added</th><th>EPSS</th><th>CVSS</th><th>Source</th></tr></thead>
                    <tbody>
                      <tr v-for="row in displayedRows" :key="row.cve_id">
                        <td><button class="text-button" type="button" @click="openDetail(row.cve_id)">{{ row.cve_id }}</button></td>
                        <td>{{ row.kev_added_at }}</td><td>{{ row.epss === null ? '—' : proportion.format(row.epss) }}</td>
                        <td>{{ row.cvss_score ?? '—' }}</td>
                        <td><button v-if="row.source_refs.length" class="text-button" type="button" :aria-label="'Evidence for ' + row.cve_id" @click="openCveEvidence(row)"><ArrowUpRight :size="16" /></button></td>
                      </tr>
                    </tbody>
                  </table>
                  <p v-else class="table-empty">{{ ready ? 'No ranked vulnerabilities match the active scope.' : 'Waiting for snapshot data.' }}</p>
                </div>
              </section>
            </div>
            <InvestigationPanel
:ready="ready" :running="running" :steps="steps" :report="report"
                                :mitigation-cve="mitigationCve" :mitigation-country="mitigationCountry" :proposal="view.proposal" :error="investigationError" :applied="proposalHistory.length"
                                @start="start" @stop="cancel" @apply="applyProposal" @inspect="inspect" />
          </div>

          <section id="sources" class="panel source-panel" aria-labelledby="sources-heading">
            <header class="panel-header">
              <div class="panel-title"><span class="icon-tile"><Database :size="18" /></span>
                <div><h2 id="sources-heading">Source coverage</h2><p>Capture status, observed records and source dates</p></div>
              </div>
            </header>
            <div class="source-grid">
              <article v-for="item in data?.coverage ?? []" :key="item.source" class="source-item">
                <div><span class="status-dot" :class="{ amber: item.status !== 'ok' }" /><strong>{{ sourceLabels[item.source] }}</strong></div>
                <p>
                  {{ item.status }}<template v-if="item.status !== 'unavailable'"> · {{ numeric.format(item.row_count) }} records</template>
                </p>
                <time v-if="item.source_date" :datetime="item.source_date">{{ item.source_date.slice(0, 10) }}</time>
                <span v-else>Source date unavailable</span>
              </article>
            </div>
          </section>
          <footer class="content-footer"><CircleHelp :size="14" /> EPSS measures likelihood of exploitation within 30 days. NVD supplies available CVSS values.</footer>
        </template>
      </div>
    </main>
    <CveDetailDrawer
      :detail="detail" :profile-id="profilesEnabled ? detailCveId : undefined" :loading="detailLoading" :error="detailError" :disabled="running"
      @close="closeDetail" @inspect="inspectDetail" @mitigate="mitigate" />
    <EvidenceDrawer :item="selectedEvidence" @close="selectedEvidence = undefined" />
  </div>
</template>

<style scoped>
.account-profile { display: flex; gap: 1rem; align-items: center; padding: 1rem; overflow-wrap: anywhere; }
.account-profile h2 { font-weight: 650; }
.profile-trigger { padding: 0; }
</style>
