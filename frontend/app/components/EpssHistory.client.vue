<script setup lang="ts">
import { ChartNoAxesCombined } from '@lucide/vue'
import type { ECharts } from 'echarts/core'
import type { HistorySelection } from '../../investigations/stream'

interface Day {
  date: string
  observation: {
    model_version: string
    observed_count: number
    mean_probability: number
    approximate_median_probability: number
    approximate_p95_probability: number
  } | null
}
interface History {
  release_id: string
  snapshot_id: string
  coverage_start: string
  coverage_end: string
  date_from: string
  date_to: string
  available_dates: number
  unavailable_dates: number
  data: Day[]
}

const emit = defineEmits<{ networkYear: [year: number]; investigate: [selection: HistorySelection] }>()
const analysisEnabled = useRuntimeConfig().public.historyAnalysisV2 === true
const auth = useOperatorAuth()
const history = shallowRef<History>()
const container = ref<HTMLElement>()
const start = ref('')
const end = ref('')
const selected = ref('')
const comparison = ref('')
const error = ref('')
const chartError = ref(false)
const loading = ref(false)
const day = computed(() => history.value?.data.find(item => item.date === selected.value))
const reference = computed(() => history.value?.data.find(item => item.date === comparison.value))
const difference = computed(() => {
  const selectedDay = day.value?.observation
  const referenceDay = reference.value?.observation
  if (!selectedDay || !referenceDay || selectedDay.model_version !== referenceDay.model_version) return null
  return (selectedDay.mean_probability - referenceDay.mean_probability) * 100
})
const percent = new Intl.NumberFormat('en-US', { style: 'percent', maximumFractionDigits: 3 })
const count = new Intl.NumberFormat('en-US')
let request: AbortController | undefined
let chart: ECharts | undefined
let resize: ResizeObserver | undefined
let disposed = false

const transitions = computed(() => {
  let previous: string | undefined
  return (history.value?.data ?? []).flatMap((item) => {
    const model = item.observation?.model_version
    if (!model || model === previous) return []
    const first = previous === undefined
    previous = model
    return first ? [] : [{ date: item.date, model }]
  })
})
const gaps = computed(() => (history.value?.data ?? []).filter(item => item.observation === null))

function draw() {
  const data = history.value?.data ?? []
  chart?.setOption({
    animation: false,
    aria: { enabled: true, description: 'Global daily EPSS with gaps on dates lacking source observations' },
    color: ['#49ddbb', '#8aa9ef', '#e7ae69'],
    grid: { left: 58, right: 22, top: 40, bottom: 36 },
    legend: { textStyle: { color: '#c9d8e5' } },
    tooltip: { trigger: 'axis', renderMode: 'richText', valueFormatter: (value: unknown) =>
      typeof value === 'number' ? percent.format(value) : 'No observation' },
    xAxis: {
      type: 'category', data: data.map(item => item.date), boundaryGap: false,
      axisLabel: { color: '#93a6ba', hideOverlap: true },
    },
    yAxis: {
      type: 'value', axisLabel: { color: '#93a6ba', formatter: (value: number) => percent.format(value) },
      splitLine: { lineStyle: { color: '#263749' } },
    },
    series: [
      { name: 'Mean', type: 'line', data: data.map(item => item.observation?.mean_probability ?? null),
        markLine: { silent: true, symbol: 'none', label: { show: false },
          data: transitions.value.map(item => ({ xAxis: item.date })) } },
      { name: 'Approx. median', type: 'line',
        data: data.map(item => item.observation?.approximate_median_probability ?? null) },
      { name: 'Approx. p95', type: 'line',
        data: data.map(item => item.observation?.approximate_p95_probability ?? null) },
    ].map(series => ({ ...series, showSymbol: data.length === 1, connectNulls: false })),
  }, true)
}

async function load(mode: 'recent' | 'all' | 'range' = 'recent') {
  request?.abort()
  if (!auth.authenticated.value || !auth.sessionIdentity.value) {
    history.value = undefined
    loading.value = false
    return
  }
  if (mode === 'range' && (!start.value || !end.value || start.value > end.value)) {
    error.value = 'Enter a valid start and end date.'
    return
  }
  const controller = new AbortController()
  request = controller
  loading.value = true
  error.value = ''
  try {
    const params = new URLSearchParams()
    if (mode === 'all') params.set('all_dates', 'true')
    if (mode === 'range') {
      params.set('date_from', start.value)
      params.set('date_to', end.value)
    }
    const result = await $fetch<History>('/api/aegis/v2/analytics/epss', {
      query: Object.fromEntries(params), headers: auth.requestHeaders(),
      retry: 0, signal: controller.signal,
    })
    if (controller.signal.aborted) return
    if (!/^[a-f0-9]{64}$/.test(result.release_id) || !/^\d+$/.test(result.snapshot_id) ||
        result.data.length > 2200 || (history.value && result.release_id !== history.value.release_id)) {
      throw new Error('EPSS release mismatch')
    }
    history.value = result
    start.value = result.date_from
    end.value = result.date_to
    selected.value = result.date_to
    comparison.value = ''
  } catch {
    if (!controller.signal.aborted) error.value = 'The selected EPSS history is unavailable.'
  } finally {
    if (!controller.signal.aborted) loading.value = false
  }
}

watch([auth.authenticated, auth.sessionIdentity], () => void load(), { immediate: true })
watch(history, draw)
onMounted(async () => {
  try {
    const [{ init, use }, { LineChart }, { GridComponent, LegendComponent, TooltipComponent, AriaComponent, MarkLineComponent }, { CanvasRenderer }] =
      await Promise.all([import('echarts/core'), import('echarts/charts'), import('echarts/components'), import('echarts/renderers')])
    if (disposed || !container.value) return
    use([LineChart, GridComponent, LegendComponent, TooltipComponent, AriaComponent, MarkLineComponent, CanvasRenderer])
    chart = init(container.value)
    draw()
    resize = new ResizeObserver(() => chart?.resize())
    resize.observe(container.value)
  } catch {
    chartError.value = true
  }
})
onUnmounted(() => {
  disposed = true
  request?.abort()
  resize?.disconnect()
  chart?.dispose()
})
</script>

<template>
  <section id="epss-history" class="panel analytics-panel" aria-labelledby="history-title" :aria-busy="loading">
    <header class="panel-header">
      <div class="panel-title">
        <span class="icon-tile"><ChartNoAxesCombined :size="18" aria-hidden="true" /></span>
        <div><h2 id="history-title">EPSS history</h2><p>FIRST EPSS · global daily probability · 30-day horizon</p></div>
      </div>
    </header>
    <form class="history-controls" @submit.prevent="load('range')">
      <label>EPSS start date<input v-model="start" type="date" :min="history?.coverage_start" :max="history?.coverage_end" required></label>
      <label>EPSS end date<input v-model="end" type="date" :min="history?.coverage_start" :max="history?.coverage_end" required></label>
      <UButton type="submit" :disabled="loading">Apply date range</UButton>
      <UButton type="button" variant="outline" :disabled="loading" @click="load('all')">Full history</UButton>
    </form>
    <div v-if="analysisEnabled && history && history.data.length <= 31" class="history-copy">
      <UButton type="button" variant="outline"
        @click="emit('investigate', { release_id: history.release_id, date_from: history.date_from, date_to: history.date_to })">
        Analyze selected EPSS dates
      </UButton>
    </div>
    <p v-if="error" class="history-copy" role="alert">{{ error }}</p>
    <p v-if="history" class="history-copy" aria-live="polite">
      {{ count.format(history.available_dates) }} observed days · {{ history.unavailable_dates }} dates absent from the source
    </p>
    <div class="analytics-chart"><div ref="container" class="visual-surface" aria-label="Global EPSS history chart" /></div>
    <p v-if="chartError" class="history-copy">Chart unavailable. Review the daily values below.</p>
    <div v-if="history" class="history-copy">
      <label>Inspect EPSS date<input v-model="selected" type="date" :min="history.date_from" :max="history.date_to"></label>
      <p v-if="day?.observation">{{ day.date }} · {{ day.observation.model_version }} ·
        {{ count.format(day.observation.observed_count) }} scores · mean {{ percent.format(day.observation.mean_probability) }}</p>
      <p v-else-if="day">{{ day.date }} · No source observation</p>
      <UButton v-if="day" type="button" variant="ghost" @click="emit('networkYear', Number(day.date.slice(0, 4)))">
        Show network context for {{ day.date.slice(0, 4) }}
      </UButton>
      <label>Compare EPSS date<input v-model="comparison" type="date" :min="history.date_from" :max="history.date_to"></label>
      <p v-if="difference !== null">Mean difference · {{ difference.toFixed(4) }} percentage points</p>
      <p v-else-if="comparison">Comparison requires two observations from the same EPSS model.</p>
      <details v-if="gaps.length"><summary>Missing dates</summary>
        <ul><li v-for="gap in gaps" :key="gap.date">{{ gap.date }}</li></ul>
      </details>
      <details v-if="transitions.length"><summary>Observed model changes</summary>
        <ul><li v-for="transition in transitions" :key="transition.date">{{ transition.date }} · {{ transition.model }}</li></ul>
      </details>
    </div>
  </section>
</template>

<style scoped>
.history-controls { display: flex; flex-wrap: wrap; align-items: end; gap: .7rem; padding: 0 1rem .7rem; }
.history-controls label, .history-copy label { display: grid; gap: .3rem; }
.history-copy { padding: .25rem 1rem .8rem; }
</style>
