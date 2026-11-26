<script setup lang="ts">
import isoCountries from 'i18n-iso-countries'
import { Globe2, Map, Radar } from '@lucide/vue'
import type { ExposureProjection, Metric, ShadowserverContext } from '../../investigations/exposure'
import { countRanges, NO_DATA, severityRanges, UNRATED } from '../../investigations/exposure'
import { demoArea, shadowserver } from '../../investigations/shadowserver'

const props = defineProps<{ projection: ExposureProjection; country?: string }>()
const emit = defineEmits<{ area: [country: string]; detail: [id: string, context: ShadowserverContext] }>()
const names = new Intl.DisplayNames(['es'], { type: 'region' })
const countries = Object.keys(isoCountries.getAlpha2Codes())
  .map(code => ({ code, name: names.of(code) ?? code })).sort((a, b) => a.name.localeCompare(b.name, 'es'))
const metric = ref<Metric>('count')
const view = ref<'globe' | 'tactical'>('globe')
const observations = computed(() => props.projection.observations)
const selected = computed(() => observations.value.find(row => row.context.area.country_iso2 === props.country))
const page = computed(() => selected.value ? demoArea(props.projection, selected.value.context) : undefined)
const period = computed(() => observations.value[0]?.context)
const GlobeView = defineAsyncComponent(() => import('./GlobeView.client.vue'))
const TacticalView = defineAsyncComponent(() => import('./TacticalView.client.vue'))

function openMarker(id: string) {
  const observation = observations.value.find(item => item.context.observation_id === id)
  if (!observation) return
  const { context } = observation
  const row = demoArea(props.projection, context).rows[0]
  emit('area', context.area.country_iso2)
  if (row) emit('detail', row.cve_id, context)
}
</script>

<template>
  <section class="panel geo-panel" aria-labelledby="exposure-title">
    <header class="panel-header">
      <div class="panel-title">
        <span class="icon-tile"><Radar :size="18" aria-hidden="true" /></span>
        <div><h2 id="exposure-title">Exposición a CVE</h2><p>Hallazgos con evidencia geográfica</p></div>
      </div>
      <div class="segmented" role="group" aria-label="Map view">
        <button type="button" :aria-pressed="view === 'globe'" @click="view = 'globe'">
          <Globe2 :size="14" aria-hidden="true" /> Globe
        </button>
        <button type="button" :aria-pressed="view === 'tactical'" @click="view = 'tactical'">
          <Map :size="14" aria-hidden="true" /> Tactical
        </button>
      </div>
    </header>
    <div class="layer-controls">
      <slot name="filters" />
      <label>Métrica
        <select v-model="metric">
          <option value="count">CVE distintas</option>
          <option value="severity">Gravedad</option>
        </select>
      </label>
      <label>País
        <select :value="country ?? ''" aria-label="Map country" @change="emit('area', ($event.target as HTMLSelectElement).value)">
          <option value="">Mundo</option>
          <option v-for="entry in countries" :key="entry.code" :value="entry.code">{{ entry.name }}</option>
        </select>
      </label>
    </div>
    <div class="geo-stage">
      <span v-if="!observations.length || (country && !selected)" class="viewport-chip">Sin datos</span>
      <ClientOnly>
        <GlobeView
          v-if="view === 'globe'" :history="observations" :country="country" :metric="metric"
          @country="emit('area', $event)" @marker="openMarker" />
        <TacticalView
          v-else :history="observations" :country="country" :metric="metric"
          @country="emit('area', $event)" @marker="openMarker" />
      </ClientOnly>
      <span class="map-attribution">Natural Earth</span>
    </div>
    <div class="layer-key" aria-label="Leyenda del mapa">
      <strong>{{ metric === 'count' ? 'CVE distintas' : 'CVSS máximo' }}</strong>
      <span v-for="range in metric === 'count' ? countRanges : severityRanges" :key="range.label">
        <i :style="{ backgroundColor: range.color }" />{{ range.label }}
      </span>
      <span v-if="metric === 'severity'"><i :style="{ backgroundColor: UNRATED }" /> Sin clasificación</span>
      <span><i :style="{ backgroundColor: NO_DATA }" /> Sin datos</span>
      <span v-if="observations.length">● Referencia visual en el centroide del país</span>
    </div>
    <div class="map-state">
      <p>
        <a :href="shadowserver.href" target="_blank" rel="noopener noreferrer">{{ shadowserver.label }}</a>
        <template v-if="period"> · {{ period.window_start }} · Publicación {{ period.publication_date }} · Cobertura parcial</template>
        <template v-else> · Sin datos para la selección</template>
      </p>
      <p v-if="metric === 'severity'">Máximo CVSS de NVD para las CVE de la muestra.</p>
      <p v-else>Identificadores CVE únicos en la muestra del día.</p>
    </div>
    <div class="map-state" aria-label="Exposición del área" aria-live="polite">
      <h3>{{ country ? names.of(country) : 'Mundo' }}</h3>
      <template v-if="selected && page">
        <ShadowserverObservation :context="selected.context" />
        <ul class="map-observations">
          <li v-for="row in page.rows" :key="row.cve_id">
            <button type="button" class="text-button" @click="emit('detail', row.cve_id, page.context)">{{ row.cve_id }}</button>
            · {{ row.cvss_score === null ? 'Sin clasificación' : 'CVSS ' + row.cvss_score }}
          </li>
        </ul>
      </template>
      <p v-else-if="!country && observations.length">Selecciona un país para consultar su exposición.</p>
      <p v-else><strong>Sin datos</strong></p>
    </div>
  </section>
</template>

<style scoped>
.layer-controls { flex-wrap: wrap; }
.layer-controls label select { margin-inline-start: .3rem; }
</style>
