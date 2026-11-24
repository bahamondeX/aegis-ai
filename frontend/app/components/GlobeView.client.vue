<script setup lang="ts">
import type { Exposure } from '../../investigations/events'
import { countryOutlines, observedCountries, type CountryFeature } from '../composables/cartography'

const props = defineProps<{ observations: Exposure[] }>()
const target = ref<HTMLElement>()
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
      .polygonStrokeColor(() => '#375967')
      .polygonsTransitionDuration(0)
      .pointOfView({ lat: 17, lng: -35, altitude: 2.05 }, 0)
    const material = widget.globeMaterial() as { color?: { set(value: string): void } }
    material.color?.set('#0c202c')
    const controls = widget.controls()
    controls.autoRotate = !media.matches
    controls.autoRotateSpeed = 0.26
    controls.enableZoom = false
    const motion = (event: MediaQueryListEvent) => {
      controls.autoRotate = !event.matches
    }
    media.addEventListener('change', motion)
    const resize = new ResizeObserver(() => {
      widget.width(element.clientWidth).height(element.clientHeight)
    })
    resize.observe(element)
    const stop = watch(() => props.observations, (rows) => {
      const observed = new Set(observedCountries(rows).map(row => row.id))
      widget.polygonCapColor((value) => observed.has((value as CountryFeature).id)
        ? '#34d9b7' : '#17333e')
    }, { immediate: true })
    cleanup = () => {
      stop()
      resize.disconnect()
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
  <div ref="target" class="visual-surface" aria-label="Interactive globe with Natural Earth boundaries" />
  <p v-if="unavailable" class="visual-fallback" role="status">WebGL globe is unavailable on this device.</p>
</template>
