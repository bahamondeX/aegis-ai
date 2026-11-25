<script setup lang="ts">
import type { Exposure } from '../../investigations/events'
import type { MapProjection } from '../../investigations/geography'
import { getAlpha2Codes } from 'i18n-iso-countries'
import { Globe2, Layers3, Map, Radar } from '@lucide/vue'

const props = defineProps<{ observations: Exposure[]; projection?: MapProjection; active: boolean; country?: string }>()
const emit = defineEmits<{ country: [iso2: string]; detail: [cve: string] }>()
const networkOn = ref(true)
const exposureOn = ref(true)
const selectedRegion = ref('')
const names = new Intl.DisplayNames(['en'], { type: 'region' })
const countries = Object.keys(getAlpha2Codes())
  .map(code => ({ code, name: names.of(code) ?? code })).sort((a, b) => a.name.localeCompare(b.name))
const percent = new Intl.NumberFormat('en', { style: 'percent', maximumFractionDigits: 1 })
const network = computed(() => props.projection?.network.records ?? [])
const regions = computed(() => [...new Set(network.value.flatMap(row => row.region ? [row.region] : []))].sort())
const displayedContext = computed(() => network.value.filter(row => selectedRegion.value
  ? row.region === selectedRegion.value : row.region === null))
const networkCountries = computed(() => networkOn.value && !selectedRegion.value ? displayedContext.value
  .filter(row => row.kind !== 'registration_country').map(row => row.country_iso2) : [])
const coverage = computed(() => props.projection?.exposure)
const showExposure = computed(() => exposureOn.value && coverage.value?.category === 'observed_exposure')
const visibleExposure = computed(() => showExposure.value && coverage.value?.state === 'observed'
  ? props.observations : [])
watch(() => props.country, () => { selectedRegion.value = '' })
const mode = ref<'globe' | 'tactical'>('globe')
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
      <select :value="country ?? ''" aria-label="Map country" @change="emit('country', ($event.target as HTMLSelectElement).value)">
        <option value="">World</option>
        <option v-for="entry in countries" :key="entry.code" :value="entry.code">{{ entry.name }}</option>
      </select>
      <select v-if="country && regions.length && networkOn" v-model="selectedRegion" aria-label="Network region">
        <option value="">All regions</option>
        <option v-for="area in regions" :key="area">{{ area }}</option>
      </select>
    </div>
    <div class="geo-stage">
      <span class="viewport-chip"><Layers3 :size="14" aria-hidden="true" /> COUNTRY OUTLINES</span>
      <ClientOnly v-if="active">
        <GlobeView v-if="mode === 'globe'" :observations="visibleExposure" :network="networkCountries" :country="country" />
        <TacticalView v-else :observations="visibleExposure" :network="networkCountries" :country="country" />
      </ClientOnly>
      <span class="map-attribution">Natural Earth</span>
    </div>
    <div class="layer-key" aria-label="Map legend">
      <span><i class="network-key" /> Published network coverage</span>
      <span><i class="aggregate-key" /> Approximate exposure area</span>
      <span><i class="unavailable-key" /> Coverage unavailable</span>
      <span><i class="zero-key" /> Measured zero</span>
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
      <p v-else><strong>Network context unavailable</strong><br>{{ projection?.network.note }}</p>
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
