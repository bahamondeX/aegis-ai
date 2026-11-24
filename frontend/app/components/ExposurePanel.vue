<script setup lang="ts">
import type { Exposure } from '../../investigations/events'
import { Globe2, Layers3, Map, Radar } from '@lucide/vue'

defineProps<{ observations: Exposure[]; availability: 'available' | 'unavailable'; active: boolean }>()
const mode = ref<'globe' | 'tactical'>('globe')
const GlobeView = defineAsyncComponent(() => import('./GlobeView.client.vue'))
const TacticalView = defineAsyncComponent(() => import('./TacticalView.client.vue'))
</script>

<template>
  <section id="exposure" class="panel geo-panel" aria-labelledby="exposure-title">
    <header class="panel-header">
      <div class="panel-title">
        <span class="icon-tile"><Radar :size="18" aria-hidden="true" /></span>
        <div><h2 id="exposure-title">Geographic exposure</h2><p>Verified observations by country</p></div>
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
    <div class="geo-stage">
      <span class="viewport-chip"><Layers3 :size="14" aria-hidden="true" /> COUNTRY OUTLINES</span>
      <ClientOnly v-if="active">
        <GlobeView v-if="mode === 'globe'" :observations="observations" />
        <TacticalView v-else :observations="observations" />
      </ClientOnly>
      <span class="map-attribution">Natural Earth</span>
    </div>
    <div v-if="active && availability === 'unavailable'" class="map-state">
      <span class="status-dot amber" />
      <p><strong>Exposure coverage unavailable</strong><br>Country outlines are shown for geographic context.</p>
    </div>
    <div v-else-if="active && !observations.length" class="map-state">
      <span class="status-dot" /><p>No verified observations match the current filters.</p>
    </div>
    <ul v-else-if="observations.length" class="map-observations">
      <li v-for="item in observations" :key="item.evidence_id">
        {{ item.country_iso2 }} · {{ item.cve_id }} · {{ item.count ?? 'Unknown count' }} {{ item.unit }}
      </li>
    </ul>
  </section>
</template>
