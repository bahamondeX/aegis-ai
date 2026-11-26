<script setup lang="ts">
interface SourceRecord {
  source: 'cve' | 'nvd' | 'kev'
  capture: string
  evidence_id: string
  source_url: string
  capture_sha256: string
  published_at: string | null
  modified_at: string | null
  status: string | null
  descriptions: unknown[]
  assessments: unknown
  weaknesses: unknown
  applicability: unknown
  required_action: string | null
  kev_added: string | null
}
interface Profile {
  release_id: string
  cve_id: string
  source_records: SourceRecord[]
  geographic_coverage: 'unavailable'
}

const props = defineProps<{ cve: string }>()
const auth = useOperatorAuth()
const profile = shallowRef<Profile>()
const error = ref('')
const loading = ref(false)
const labels = { cve: 'CVE Program', kev: 'CISA KEV', nvd: 'NIST NVD' }
let request: AbortController | undefined

function description(row: SourceRecord): string {
  return row.descriptions.flatMap((item) => {
    if (typeof item !== 'object' || item === null || !('value' in item) || typeof item.value !== 'string') return []
    return [item.value]
  })[0] ?? 'Description unavailable.'
}

function citation(row: SourceRecord): string {
  if (row.source === 'kev') return 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
  const id = encodeURIComponent(props.cve)
  return row.source === 'cve' ? `https://www.cve.org/CVERecord?id=${id}` : `https://nvd.nist.gov/vuln/detail/${id}`
}

async function load() {
  request?.abort()
  profile.value = undefined
  error.value = ''
  loading.value = false
  if (!auth.authenticated.value || !auth.sessionIdentity.value) return
  const controller = new AbortController()
  request = controller
  loading.value = true
  const id = props.cve
  try {
    const current = await $fetch<Profile>('/api/aegis/v2/cves/' + encodeURIComponent(id), {
      headers: auth.requestHeaders(), retry: 0, signal: controller.signal,
    })
    if (controller.signal.aborted) return
    if (current.cve_id !== id || !/^[a-f0-9]{64}$/.test(current.release_id) ||
        current.geographic_coverage !== 'unavailable' || current.source_records.length > 8) throw new Error()
    profile.value = current
  } catch {
    if (!controller.signal.aborted) error.value = 'Official source profile unavailable.'
  } finally {
    if (!controller.signal.aborted) loading.value = false
  }
}

watch([() => props.cve, auth.authenticated, auth.sessionIdentity], load, { immediate: true })
onUnmounted(() => request?.abort())
</script>

<template>
  <section class="profile-sources" aria-label="Official source profile" :aria-busy="loading">
    <h3>Official source profile</h3>
    <p v-if="loading" role="status">Loading pinned source records…</p>
    <p v-if="error" role="alert">{{ error }}</p>
    <template v-if="profile">
      <p>{{ profile.source_records.length }} source records · CVE exposure geography unavailable</p>
      <details v-for="row in profile.source_records" :key="row.evidence_id">
        <summary>{{ labels[row.source] }} · {{ row.capture.split('/').slice(1).join('/') }}</summary>
        <p>{{ description(row) }}</p>
        <dl>
          <dt>Published</dt><dd>{{ row.published_at?.slice(0, 10) ?? 'Unavailable' }}</dd>
          <dt>Updated</dt><dd>{{ row.modified_at?.slice(0, 10) ?? 'Unavailable' }}</dd>
          <dt>Status</dt><dd>{{ row.status ?? 'Unavailable' }}</dd>
          <dt>Evidence</dt><dd><code>{{ row.evidence_id }}</code></dd>
          <dt>Capture SHA-256</dt><dd><code>{{ row.capture_sha256 }}</code></dd>
        </dl>
        <p v-if="row.kev_added">KEV listed {{ row.kev_added }}.</p>
        <p v-if="row.required_action">{{ row.required_action }}</p>
        <details v-for="field in (['assessments', 'weaknesses', 'applicability'] as const)" :key="field">
          <summary>{{ { assessments: 'Source assessments', weaknesses: 'Source weaknesses', applicability: 'Source applicability criteria' }[field] }}</summary>
          <pre v-if="row[field] !== null">{{ JSON.stringify(row[field], null, 2) }}</pre>
          <p v-else>Unavailable in this source record.</p>
        </details>
        <a :href="citation(row)" target="_blank" rel="noopener noreferrer">Open official source</a>
      </details>
    </template>
  </section>
</template>

<style scoped>
.profile-sources details { padding: .45rem 0; }
.profile-sources pre { overflow: auto; max-height: 18rem; white-space: pre-wrap; }
.profile-sources code { overflow-wrap: anywhere; }
</style>
