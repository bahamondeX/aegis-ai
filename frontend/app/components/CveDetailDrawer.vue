<script setup lang="ts">
import type { CveDetail } from '../../investigations/geography'

const props = defineProps<{ detail?: CveDetail; loading: boolean; error: string; disabled: boolean }>()
const emit = defineEmits<{ close: []; mitigate: [detail: CveDetail]; inspect: [id: string] }>()
const dialog = ref<HTMLDialogElement>()
const open = computed(() => props.loading || !!props.error || !!props.detail)
const applicability = computed(() => {
  const groups = new Map<string, { version: string; row: CveDetail['applicability'][number]; count: number }>()
  for (const row of props.detail?.applicability ?? []) {
    const version = [
      row.version,
      row.start_including && '≥ ' + row.start_including,
      row.start_excluding && '> ' + row.start_excluding,
      row.end_including && '≤ ' + row.end_including,
      row.end_excluding && '< ' + row.end_excluding,
    ].filter(Boolean).join(', ') || 'Version unspecified'
    const key = JSON.stringify([row.vendor, row.product, version, row.evidence_id])
    const previous = groups.get(key)
    if (previous) previous.count++
    else groups.set(key, { version, row, count: 1 })
  }
  return [...groups.values()]
})
const percent = new Intl.NumberFormat('en-US', { style: 'percent', maximumFractionDigits: 3 })
watch(open, async (visible) => {
  await nextTick()
  if (!dialog.value) return
  if (visible && !dialog.value.open) dialog.value.showModal()
  if (!visible && dialog.value.open) dialog.value.close()
}, { immediate: true, flush: 'post' })
</script>

<template>
  <dialog ref="dialog" class="panel cve-detail" aria-label="CVE detail" @cancel.prevent="emit('close')">
    <header>
      <h2>{{ detail?.vulnerability.cve_id ?? 'CVE detail' }}</h2>
      <button type="button" class="text-button" @click="emit('close')">Close</button>
    </header>
    <p v-if="loading" role="status">Verifying the selected CVE…</p>
    <p v-else-if="error" role="alert">{{ error }}</p>
    <template v-else-if="detail">
      <p>{{ detail.vulnerability.description }}</p>
      <dl class="cve-facts">
        <div><dt>KEV</dt><dd>{{ detail.vulnerability.kev ? 'Listed by CISA' : 'Outside catalog' }}</dd></div>
        <div><dt>CVSS</dt><dd class="cvss-value">{{ detail.vulnerability.cvss_score ?? 'Unavailable' }}</dd>
          <dd v-if="detail.vulnerability.cvss_version">{{ detail.vulnerability.cvss_version }} · {{ detail.vulnerability.cvss_source }}</dd>
        </div>
        <div><dt>EPSS probability</dt><dd>{{ detail.vulnerability.epss === null ? 'Unavailable' : percent.format(detail.vulnerability.epss) }}</dd>
          <dd v-if="detail.vulnerability.score_date"><time :datetime="detail.vulnerability.score_date">{{ detail.vulnerability.score_date }}</time></dd>
        </div>
      </dl>
      <h3>Affected products and versions</h3>
      <p v-if="!detail.products.length && !detail.applicability.length">Product applicability is unknown for this snapshot.</p>
      <p v-for="product in detail.products" :key="product.target_id">{{ product.vendor }} / {{ product.target_label }} · CISA catalog product</p>
      <p v-if="!detail.applicability.length">Affected versions are unavailable.</p>
      <details v-else class="applicability">
        <summary>Review NVD product and version criteria</summary>
        <ul>
          <li v-for="entry in applicability" :key="entry.row.configuration_path">
            {{ entry.row.vendor }} / {{ entry.row.product }} · {{ entry.version }}
            <small v-if="entry.count > 1"> · {{ entry.count }} published criteria</small>
            <button class="text-button" type="button" @click="emit('inspect', entry.row.evidence_id)">NVD evidence</button>
          </li>
        </ul>
        <p>NVD configurations can have additional conditions. Confirm applicability against your inventory.</p>
      </details>
      <h3>Geographic evidence · {{ detail.geography.country_iso2 ?? 'Worldwide' }}</h3>
      <p>{{ detail.geography.reason ?? detail.geography.state }}</p>
      <h3>Source evidence</h3>
      <div class="cve-source-actions">
        <button
          v-for="item in detail.evidence" :key="item.evidence_id" class="text-button" type="button"
          @click="emit('inspect', item.evidence_id)"
        >{{ item.source.toUpperCase() }} · {{ item.evidence_id.slice(0, 7) }}</button>
      </div>
      <p v-if="!detail.mitigation">Archived remediation instructions are unavailable for this release.</p>
      <UButton class="primary-action" :disabled="disabled || !detail.evidence.length" @click="emit('mitigate', detail)">
        How to mitigate
      </UButton>
    </template>
  </dialog>
</template>
