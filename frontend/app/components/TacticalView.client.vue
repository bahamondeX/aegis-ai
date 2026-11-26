<script setup lang="ts">
import 'maplibre-gl/dist/maplibre-gl.css'
import workerUrl from 'maplibre-gl/dist/maplibre-gl-worker.mjs?url'
import type { Exposure } from '../../investigations/events'
import { countryBorders, countryFeatures, countryOutlines, observedCountries } from '../composables/cartography'

const props = defineProps<{ observations: Exposure[]; network: string[]; country?: string }>()
const target = ref<HTMLElement>()
const unavailable = ref(false)
const rendered = ref(false)
const landFeatures = ref(0)
let cleanup: (() => void) | undefined
let disposed = false
onMounted(async () => {
  try {
    const [{ Map, setWorkerUrl }, { MapboxOverlay }, { GeoJsonLayer }] = await Promise.all([
      import('maplibre-gl'), import('@deck.gl/mapbox'), import('@deck.gl/layers'),
    ])
    const element = target.value
    if (disposed || !element) return
    setWorkerUrl(workerUrl)
    const map = new Map({
      container: element, center: [-11, 21], zoom: 0.95, minZoom: 0.5,
      attributionControl: false,
      cooperativeGestures: true,
      style: {
        version: 8,
        sources: {
          countries: { type: 'geojson', data: countryOutlines() },
          borders: { type: 'geojson', data: countryBorders() },
        },
        layers: [
          { id: 'ocean', type: 'background', paint: { 'background-color': '#101722' } },
          { id: 'land', type: 'fill', source: 'countries', paint: { 'fill-color': '#23323e' } },
          { id: 'borders', type: 'line', source: 'borders', paint: { 'line-color': '#477283', 'line-width': 0.8 } },
        ],
      },
    })
    const overlay = new MapboxOverlay({ interleaved: false, layers: [] })
    const stop = watch(() => [props.observations, props.network, props.country] as const, ([rows, countries, country]) => {
      if (!rows.length && !countries.length && !country) {
        if (map.hasControl(overlay)) map.removeControl(overlay)
        return
      }
      if (!map.hasControl(overlay)) map.addControl(overlay)
      overlay.setProps({ layers: [
        new GeoJsonLayer({
          id: 'published-network-context', data: countryFeatures(countries),
          getFillColor: [73, 115, 145, 125], getLineColor: [121, 152, 176, 255],
          lineWidthMinPixels: 1.4,
        }),
        new GeoJsonLayer({
          id: 'approximate-exposure', data: observedCountries(rows),
          getFillColor: [224, 162, 79, 135], getLineColor: [234, 186, 115, 255],
          lineWidthMinPixels: 1.6,
        }),
        new GeoJsonLayer({
          id: 'selected-country-outline', data: country ? countryFeatures([country]) : [],
          filled: false, getLineColor: [210, 226, 243, 255], lineWidthMinPixels: 1.5,
        }),
      ] })
    }, { immediate: true })
    map.on('error', (event) => {
      console.warn('Tactical map:', event.error.message)
      unavailable.value = true
    })
    map.on('idle', () => {
      landFeatures.value = map.queryRenderedFeatures({ layers: ['land'] }).length
      rendered.value = !unavailable.value && landFeatures.value > 0
    })
    const resize = new ResizeObserver(() => map.resize())
    resize.observe(element)
    cleanup = () => {
      stop()
      resize.disconnect()
      if (map.hasControl(overlay)) map.removeControl(overlay)
      map.remove()
    }
  } catch (error) {
    console.warn('Tactical map:', error instanceof Error ? error.message : 'initialization failed')
    unavailable.value = true
  }
})
onUnmounted(() => {
  disposed = true
  cleanup?.()
})
</script>

<template>
  <div
    ref="target"
    class="visual-surface"
    :data-rendered="rendered"
    :data-land-features="landFeatures"
    aria-label="Tactical map with Natural Earth boundaries"
  />
  <p v-if="unavailable" class="visual-fallback" role="status">WebGL tactical map is unavailable on this device.</p>
</template>
