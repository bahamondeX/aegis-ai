interface AnnualEconomy {
  economy_code: string
  alpha2: string
  canonical_iso2: string | null
  name: string
}

interface Observation {
  economy: AnnualEconomy
  value: number | null
  availability: 'observed' | 'measured_zero' | 'unavailable'
}

interface AnnualNetwork {
  release_id: string
  year: number
  available_years: number[]
  citation: string
  source: 'World Bank WDI / ITU'
  source_date: string
  unit: 'mobile cellular subscriptions per 100 people'
  granularity: 'year'
  economies_in_scope: number
  economies_with_values: number
  data: Observation[]
}

export function useAnnualNetwork(enabled: Ref<boolean>) {
  const auth = useOperatorAuth()
  const configured = useRuntimeConfig().public.networkContextV2 === true
  const year = ref(2024)
  const data = shallowRef<AnnualNetwork>()
  const years = shallowRef<number[]>([2024])
  const error = ref('')
  const loading = ref(false)
  watch([enabled, year, auth.sessionIdentity, auth.authenticated], async ([visible, selected, token, approved], _, onCleanup) => {
    if (!configured || !visible || !approved || !token) {
      data.value = undefined
      loading.value = false
      error.value = ''
      return
    }
    const controller = new AbortController()
    onCleanup(() => controller.abort())
    error.value = ''
    loading.value = true
    try {
      const response = await fetch('/api/aegis/v2/network?year=' + encodeURIComponent(selected), {
        headers: auth.requestHeaders(), signal: controller.signal, cache: 'no-store',
      })
      if (!response.ok) throw new Error('Annual network context is unavailable.')
      const body = await response.json() as AnnualNetwork
      if (controller.signal.aborted) return
      if (!/^[a-f0-9]{64}$/.test(body.release_id) || body.year !== selected || body.granularity !== 'year' ||
          !Array.isArray(body.data) || body.data.length > 300 || body.data.length !== body.economies_in_scope ||
          !Array.isArray(body.available_years) || body.available_years.length > 141 ||
          body.unit !== 'mobile cellular subscriptions per 100 people' ||
          body.citation !== 'https://data.worldbank.org/indicator/IT.CEL.SETS.P2' ||
          body.source !== 'World Bank WDI / ITU' ||
          (data.value && body.release_id !== data.value.release_id)) throw new Error('Annual data release could not be verified.')
      data.value = body
      years.value = body.available_years
    } catch (cause) {
      if (!controller.signal.aborted) error.value = cause instanceof Error ? cause.message : 'Annual network context is unavailable.'
    } finally {
      if (!controller.signal.aborted) loading.value = false
    }
  }, { immediate: true })
  const current = computed(() => data.value?.year === year.value ? data.value : undefined)
  return { configured, year, data: current, years, loading, error }
}
