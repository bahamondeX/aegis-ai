<script setup lang="ts">
import { ChartNoAxesCombined } from '@lucide/vue'
import type { ECharts } from 'echarts/core'
import type { Vulnerability } from '../composables/useDashboard'

const props = defineProps<{ rows: Vulnerability[] }>()
const container = ref<HTMLElement>()
const noChart = ref(false)
const scored = computed(() => props.rows.filter(row => row.epss !== null))
let chart: ECharts | undefined
let resize: ResizeObserver | undefined
let disposed = false

function draw() {
  const data = scored.value
  chart?.setOption({
    animation: !window.matchMedia('(prefers-reduced-motion: reduce)').matches,
    aria: { enabled: true, description: 'EPSS by CVE in the visible cohort, in vulnerability rank order' },
    color: ['#45dfbd'],
    grid: { left: 46, right: 20, top: 18, bottom: 33 },
    tooltip: {
      trigger: 'axis', renderMode: 'richText',
      backgroundColor: '#111d2c', borderColor: '#2c4a55', textStyle: { color: '#dce9ef' },
    },
    xAxis: {
      type: 'category', data: data.map(row => row.cve_id),
      boundaryGap: false, axisLabel: { color: '#8195a9', margin: 12, hideOverlap: true },
      axisLine: { lineStyle: { color: '#2a3d50' } },
    },
    yAxis: {
      type: 'value', min: 0, max: 1, splitNumber: 4,
      axisLabel: { formatter: '{value}', color: '#8195a9' },
      splitLine: { lineStyle: { color: '#243447', type: 'dashed' } },
    },
    series: [{
      type: 'line', name: 'EPSS', data: data.map(row => row.epss),
      symbolSize: 4, showSymbol: data.length < 15,
      lineStyle: { width: 2, color: '#48ddba' },
      areaStyle: { color: {
        type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
        colorStops: [{ offset: 0, color: 'rgba(72, 221, 186, .38)' }, { offset: 1, color: 'rgba(72, 221, 186, .015)' }],
      } },
    }],
  }, true)
}
onMounted(async () => {
  try {
    const [{ init, use }, { LineChart }, { GridComponent, TooltipComponent, AriaComponent }, { CanvasRenderer }] =
      await Promise.all([
        import('echarts/core'), import('echarts/charts'), import('echarts/components'), import('echarts/renderers'),
      ])
    if (disposed || !container.value) return
    use([LineChart, GridComponent, TooltipComponent, AriaComponent, CanvasRenderer])
    chart = init(container.value)
    draw()
    resize = new ResizeObserver(() => chart?.resize())
    resize.observe(container.value)
  } catch {
    noChart.value = true
  }
})
watch(scored, draw)
onUnmounted(() => {
  disposed = true
  resize?.disconnect()
  chart?.dispose()
})
</script>

<template>
  <section class="panel analytics-panel" aria-labelledby="analytics-title">
    <header class="panel-header">
      <div class="panel-title">
        <span class="icon-tile"><ChartNoAxesCombined :size="18" aria-hidden="true" /></span>
        <div><h2 id="analytics-title">Exploit probability</h2><p>FIRST EPSS for scored CVEs in the current view</p></div>
      </div>
      <span v-if="scored.length" class="small-count">{{ scored.length }} SCORED</span>
    </header>
    <div class="analytics-chart">
      <div ref="container" class="visual-surface" aria-label="EPSS chart by vulnerability rank" />
      <p v-if="!scored.length || noChart" class="visual-fallback">
        {{ noChart ? 'Chart unavailable. EPSS values are listed in the ranked cohort.' : 'No EPSS scores match this view.' }}
      </p>
    </div>
  </section>
</template>
