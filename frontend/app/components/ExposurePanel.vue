<script setup lang="ts">
import type { Exposure } from '../../investigations/events'
import type { MapProjection } from '../../investigations/geography'
import { getAlpha2Codes } from 'i18n-iso-countries'
import { Globe2, GripHorizontal, Layers3, Map, Maximize, Minimize, Radar } from '@lucide/vue'

const props = defineProps<{ observations: Exposure[]; projection?: MapProjection; active: boolean; country?: string; historyYear?: number }>()
const emit = defineEmits<{ country: [iso2: string]; detail: [cve: string] }>()
const networkOn = ref(true)
const exposureOn = ref(true)
const annualOn = ref(true)
const { configured: annualEnabled, year: networkYear, years: networkYears, data: annual, loading: annualLoading, error: annualError }
  = useAnnualNetwork(computed(() => networkOn.value && annualOn.value))
watch(() => props.historyYear, (year) => {
  if (year !== undefined && annualEnabled) {
    annualOn.value = true
    networkOn.value = true
    networkYear.value = year
  }
})
const canvasMounted = ref(false)
watch(() => props.active, active => { if (active) canvasMounted.value = true }, { immediate: true })
const annualValue = computed(() => props.country ? annual.value?.data.find(item => item.economy.canonical_iso2 === props.country) : undefined)
const number = new Intl.NumberFormat('en', { maximumFractionDigits: 2 })
const selectedRegion = ref('')
const names = new Intl.DisplayNames(['en'], { type: 'region' })
const countries = Object.keys(getAlpha2Codes())
  .map(code => ({ code, name: names.of(code) ?? code })).sort((a, b) => a.name.localeCompare(b.name))
const percent = new Intl.NumberFormat('en', { style: 'percent', maximumFractionDigits: 1 })
const network = computed(() => props.projection?.network.records ?? [])
const regions = computed(() => [...new Set(network.value.flatMap(row => row.region ? [row.region] : []))].sort())
const displayedContext = computed(() => network.value.filter(row => selectedRegion.value
  ? row.region === selectedRegion.value : row.region === null))
const networkCountries = computed(() => networkOn.value && !selectedRegion.value ? [
  ...displayedContext.value.filter(row => row.kind !== 'registration_country').map(row => row.country_iso2),
  ...(annualOn.value ? annual.value?.data.flatMap(row => row.value !== null && row.economy.canonical_iso2 ? [row.economy.canonical_iso2] : []) ?? [] : []),
] : [])
const coverage = computed(() => props.projection?.exposure)
const showExposure = computed(() => exposureOn.value && coverage.value?.category === 'observed_exposure')
const visibleExposure = computed(() => props.active && showExposure.value && coverage.value?.state === 'observed'
  ? props.observations : [])
watch(() => props.country, () => { selectedRegion.value = '' })
const mode = ref<'globe' | 'tactical'>('globe')
const stage = ref<HTMLElement>()
const height = ref<number>()
const fullscreen = ref(false)
const fullscreenError = ref(false)
let drag: { pointer: number; startY: number; height: number } | undefined

function setHeight(next: number) {
  height.value = Math.round(Math.max(260, Math.min(720, next)))
}

function resizeStart(event: PointerEvent) {
  if (event.button !== 0 || !stage.value) return
  drag = { pointer: event.pointerId, startY: event.clientY, height: stage.value.clientHeight }
  const handle = event.currentTarget as HTMLElement
  handle.setPointerCapture(event.pointerId)
}

function resizeMove(event: PointerEvent) {
  if (drag?.pointer === event.pointerId) setHeight(drag.height + event.clientY - drag.startY)
}

function resizeEnd(event: PointerEvent) {
  if (drag?.pointer === event.pointerId) drag = undefined
}

function resizeKey(event: KeyboardEvent) {
  if ((event.key === 'ArrowDown' || event.key === 'ArrowUp') && stage.value) {
    event.preventDefault()
    setHeight(stage.value.clientHeight + (event.key === 'ArrowDown' ? 32 : -32))
  }
}

function syncFullscreen() {
  fullscreen.value = document.fullscreenElement === stage.value
}

async function toggleFullscreen() {
  if (!stage.value) return
  fullscreenError.value = false
  try {
    if (fullscreen.value) await document.exitFullscreen()
    else await stage.value.requestFullscreen()
  } catch {
    fullscreenError.value = true
  }
}

onMounted(() => document.addEventListener('fullscreenchange', syncFullscreen))
onUnmounted(() => document.removeEventListener('fullscreenchange', syncFullscreen))
const GlobeView = defineAsyncComponent(() => import('./GlobeView.client.vue'))
const TacticalView = defineAsyncComponent(() => import('./TacticalView.client.vue'))
</script>

<template>
  <section id="exposure" class="panel geo-panel" aria-labelledby="exposure-title">
    <header class="panel-header">
      <div class="panel-title">
        <span class="icon-tile"><Radar :size="18" aria-hidden="true" /></span>
        <div><h2 id="exposure-title">Geographic intelligence</h2><p>Network context and CVE evidence</p></div>
      </div>
      <div class="segmented" role="group" aria-label="Map view">
        <button type="button" :aria-pressed="mode === 'globe'" @click="mode = 'globe'">
          <Globe2 :size="14" aria-hidden="true" /> Globe
        </button>
        <button type="button" :aria-pressed="mode === 'tactical'" @click="mode = 'tactical'">
          <Map :size="14" aria-hidden="true" /> Tactical
        </button>
      </div>
    </header>
    <div class="layer-controls">
      <label><input v-model="networkOn" type="checkbox"> Network context</label>
      <label><input v-model="exposureOn" type="checkbox"> CVE geographic evidence</label>
      <label v-if="annualEnabled && networkOn"><input v-model="annualOn" type="checkbox"> Mobile subscriptions</label>
      <select v-if="annualEnabled && networkOn && annualOn" v-model.number="networkYear" aria-label="Network observation year">
        <option v-if="!networkYears.includes(networkYear)" :value="networkYear">{{ networkYear }} · unavailable</option>
        <option v-for="year in networkYears" :key="year" :value="year">{{ year }}</option>
      </select>
      <select :value="country ?? ''" aria-label="Map country" @change="emit('country', ($event.target as HTMLSelectElement).value)">
        <option value="">World</option>
        <option v-for="entry in countries" :key="entry.code" :value="entry.code">{{ entry.name }}</option>
      </select>
      <select v-if="country && regions.length && networkOn" v-model="selectedRegion" aria-label="Network region">
        <option value="">All regions</option>
        <option v-for="area in regions" :key="area">{{ area }}</option>
      </select>
    </div>
    <div ref="stage" class="geo-stage" :style="height === undefined ? undefined : { height: height + 'px' }">
      <span class="viewport-chip"><Layers3 :size="14" aria-hidden="true" /> COUNTRY OUTLINES</span>
      <ClientOnly v-if="canvasMounted">
        <GlobeView v-if="mode === 'globe'" :observations="visibleExposure" :network="networkCountries" :country="country" @country="emit('country', $event)" />
        <TacticalView v-else :observations="visibleExposure" :network="networkCountries" :country="country" />
      </ClientOnly>
      <div class="map-buttons fullscreen-button">
        <button type="button" :aria-label="fullscreen ? 'Exit fullscreen map' : 'Fullscreen map'" @click="toggleFullscreen">
          <Minimize v-if="fullscreen" :size="16" aria-hidden="true" />
          <Maximize v-else :size="16" aria-hidden="true" />
        </button>
      </div>
      <span class="map-attribution">Natural Earth</span>
      <p v-if="fullscreenError" class="visual-fallback" role="status">Fullscreen is unavailable in this browser.</p>
    </div>
    <button
      class="map-resize" type="button" aria-label="Resize map height. Drag or use Up and Down arrows."
      @pointerdown="resizeStart" @pointermove="resizeMove" @pointerup="resizeEnd" @lostpointercapture="resizeEnd"
      @pointercancel="resizeEnd" @keydown="resizeKey"><GripHorizontal :size="17" aria-hidden="true" /></button>
    <div class="layer-key" aria-label="Map legend">
      <span><i class="network-key" /> Published network context</span>
      <span><i class="aggregate-key" /> Approximate exposure area</span>
      <span><i class="unavailable-key" /> Coverage unavailable</span>
      <span><i class="zero-key" /> Measured zero</span>
    </div>
    <div v-if="annualEnabled && networkOn && annualOn" class="map-state" aria-live="polite">
      <p v-if="annualLoading">Loading {{ networkYear }} network observations</p>
      <p v-else-if="annualError" role="status">{{ annualError }}</p>
      <p v-else-if="annual" aria-label="Annual WDI network context">
        <strong>{{ annual.year }} · {{ annual.unit }}</strong><br>
        <template v-if="country">{{ names.of(country) }} · {{ annualValue?.value === null || annualValue?.value === undefined ? 'Observation unavailable' : number.format(annualValue.value) }}</template>
        <template v-else>{{ annual.economies_with_values }} of {{ annual.economies_in_scope }} economies reported values</template><br>
        <a :href="annual.citation" rel="noreferrer noopener" target="_blank">{{ annual.source }}</a> · Published {{ annual.source_date }} · CC BY 4.0
      </p>
    </div>
    <div v-if="active && networkOn" class="map-state">
      <div v-if="displayedContext.length">
        <p><strong>{{ selectedRegion || 'Published network coverage' }}</strong></p>
        <ul class="context-records">
          <li v-for="record in displayedContext" :key="record.record_id">
            <strong>{{ record.operator || names.of(record.country_iso2) }}</strong>
            · {{ { operational_presence: 'Operational presence', published_coverage: 'Published coverage', registration_country: 'Country of registration' }[record.kind] }}
            <br>{{ record.reporting_year }} · {{ record.population_coverage === null ? '' : percent.format(record.population_coverage) + ' · ' }}{{ record.scope }}
            <br><a :href="record.publication" rel="noreferrer noopener" target="_blank">{{ record.publisher }}</a> · {{ record.license }}
            · Publication {{ record.source_date }}
          </li>
        </ul>
        <p v-if="selectedRegion">Region shown in the source records. The map retains the country boundary.</p>
      </div>
      <p v-else><strong>{{ annualEnabled ? 'LTE population coverage unavailable' : 'Network context unavailable' }}</strong><br>{{ projection?.network.note }}</p>
    </div>
    <div v-if="active && showExposure" class="map-state">
      <p v-if="coverage?.state === 'measured_zero'"><strong>Measured zero</strong> · {{ coverage.count }} {{ coverage.unit }} · {{ coverage.window_start }} through {{ coverage.window_end }}</p>
      <p v-else-if="!coverage || coverage.state === 'unavailable'"><strong>Exposure coverage unavailable</strong><br>{{ coverage?.reason }}</p>
      <ul v-else-if="observations.length" class="map-observations">
        <li v-for="item in observations" :key="item.evidence_id">
          <button type="button" class="text-button" @click="emit('detail', item.cve_id)">{{ item.cve_id }}</button>
          · {{ item.country_iso2 }} · {{ item.count ?? 'Unknown count' }} {{ item.unit }} · {{ item.snapshot_at }} · {{ item.source }}
        </li>
      </ul>
    </div>
  </section>
</template>

<style scoped>
.geo-stage:fullscreen { width: 100%; height: 100% !important; }
.fullscreen-button { position: absolute; z-index: 3; left: 9px; bottom: 9px; }
.map-resize { display: grid; place-items: center; width: 100%; min-height: 24px; border-block: 1px solid #283745; color: #90b6c5; cursor: ns-resize; touch-action: none; }
.map-resize:hover, .map-resize:focus-visible { background: #1b3338; }
</style>
