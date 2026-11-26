<script setup lang="ts">
import { Minus, Plus, RotateCcw } from '@lucide/vue'
import { numericToAlpha2 } from 'i18n-iso-countries'
import type { Exposure } from '../../investigations/events'
import { countryFeatures, countryOutlines, observedCountries, type CountryFeature } from '../composables/cartography'

const props = defineProps<{ observations: Exposure[]; network: string[]; country?: string }>()
const emit = defineEmits<{ country: [iso2: string] }>()
const target = ref<HTMLElement>()
const initialView = { lat: 17, lng: -35, altitude: 2.05 }
const ready = ref(false)
let viewAction: ((action: 'in' | 'out' | 'reset' | 'left' | 'right' | 'up' | 'down') => void) | undefined

function navigate(event: KeyboardEvent) {
  const actions = { ArrowLeft: 'left', ArrowRight: 'right', ArrowUp: 'up', ArrowDown: 'down', '+': 'in', '-': 'out', Home: 'reset' } as const
  const action = actions[event.key as keyof typeof actions]
  if (action && viewAction) {
    event.preventDefault()
    viewAction(action)
  }
}
const unavailable = ref(false)
let cleanup: (() => void) | undefined
let disposed = false

onMounted(async () => {
  try {
    const { default: Globe } = await import('globe.gl')
    const element = target.value
    if (disposed || !element) return
    const media = window.matchMedia('(prefers-reduced-motion: reduce)')
    const widget = new Globe(element, { animateIn: !media.matches, waitForGlobeReady: false })
      .backgroundColor('#101722')
      .showGraticules(true)
      .atmosphereColor('#2c9da3')
      .atmosphereAltitude(0.16)
      .polygonsData(countryOutlines().features)
      .polygonAltitude(0.008)
      .polygonCapColor(() => '#17333e')
      .polygonSideColor(() => 'rgba(21, 43, 57, 0.25)')
      .polygonStrokeColor(() => '#526474')
      .polygonsTransitionDuration(0)
      .pointOfView(initialView, 0)
      .onPolygonClick((value) => {
        const feature = value as CountryFeature
        const code = feature.id === undefined ? undefined : numericToAlpha2(feature.id)
        if (code) emit('country', code)
      })
      .onZoom((view) => {
        element.dataset.altitude = String(view.altitude)
        element.dataset.longitude = String(view.lng)
      })
    const material = widget.globeMaterial() as { color?: { set(value: string): void } }
    material.color?.set('#0c202c')
    const controls = widget.controls()
    controls.autoRotate = !media.matches
    controls.autoRotateSpeed = 0.26
    controls.enableZoom = true
    controls.minDistance = 105
    controls.maxDistance = 620
    viewAction = (action) => {
      if (action === 'reset') {
        widget.pointOfView(initialView, 0)
        return
      }
      const view = widget.pointOfView()
      if (action === 'in' || action === 'out') {
        const altitude = Math.min(5.2, Math.max(0.15, view.altitude * (action === 'in' ? 0.76 : 1.3)))
        widget.pointOfView({ ...view, altitude }, 0)
      } else {
        const lng = view.lng + (action === 'left' ? -15 : action === 'right' ? 15 : 0)
        const lat = Math.max(-85, Math.min(85, view.lat + (action === 'up' ? 10 : action === 'down' ? -10 : 0)))
        widget.pointOfView({ ...view, lat, lng }, 0)
      }
    }
    element.dataset.altitude = String(initialView.altitude)
    element.dataset.longitude = String(initialView.lng)
    ready.value = true
    const motion = (event: MediaQueryListEvent) => {
      controls.autoRotate = !event.matches
    }
    media.addEventListener('change', motion)
    const resize = new ResizeObserver(() => {
      widget.width(element.clientWidth).height(element.clientHeight)
    })
    resize.observe(element)
    const visible = new IntersectionObserver(([entry]) => {
      if (entry?.isIntersecting) widget.resumeAnimation()
      else widget.pauseAnimation()
    })
    visible.observe(element)
    const canvas = widget.renderer().domElement
    const contextLost = (event: Event) => { event.preventDefault(); unavailable.value = true }
    const contextRestored = () => { unavailable.value = false; widget.resumeAnimation() }
    canvas.addEventListener('webglcontextlost', contextLost)
    canvas.addEventListener('webglcontextrestored', contextRestored)
    const stop = watch(() => [props.observations, props.network, props.country] as const, ([rows, countries, country]) => {
      const observed = new Set(observedCountries(rows).map(row => row.id))
      const context = new Set(countryFeatures(countries).map(row => row.id))
      const selected = country ? countryFeatures([country])[0]?.id : undefined
      widget.polygonCapColor((value) => {
        const code = (value as CountryFeature).id
        return observed.has(code) ? '#ac7330' : context.has(code) ? '#385a74' : '#23323e'
      }).polygonStrokeColor((value) => {
        const code = (value as CountryFeature).id
        return code && code === selected ? '#dbe7f1' : context.has(code) ? '#83a6c0' : '#526474'
      })
    }, { immediate: true })
    cleanup = () => {
      stop()
      resize.disconnect()
      visible.disconnect()
      canvas.removeEventListener('webglcontextlost', contextLost)
      canvas.removeEventListener('webglcontextrestored', contextRestored)
      media.removeEventListener('change', motion)
      widget.pauseAnimation()
      widget.controls().dispose()
      widget.renderer().dispose()
      widget.renderer().forceContextLoss()
      element.replaceChildren()
    }
  } catch {
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
    ref="target" class="visual-surface" aria-label="Interactive globe with Natural Earth boundaries"
    :tabindex="ready ? 0 : undefined" @keydown="navigate" />
  <div v-if="ready && !unavailable" class="map-buttons globe-buttons" role="group" aria-label="Globe camera">
    <button type="button" aria-label="Zoom in" @click="viewAction?.('in')"><Plus :size="17" aria-hidden="true" /></button>
    <button type="button" aria-label="Zoom out" @click="viewAction?.('out')"><Minus :size="17" aria-hidden="true" /></button>
    <button type="button" aria-label="Reset globe camera" @click="viewAction?.('reset')"><RotateCcw :size="16" aria-hidden="true" /></button>
  </div>
  <p v-if="unavailable" class="visual-fallback" role="status">WebGL globe is unavailable on this device.</p>
</template>

<style scoped>
.globe-buttons { position: absolute; z-index: 3; top: 9px; right: 9px; flex-direction: column; }
.visual-surface:focus-visible { outline: 2px solid #86e3d4; outline-offset: -3px; }
</style>
