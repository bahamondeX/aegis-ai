<script setup lang="ts">
import { ExternalLink, Fingerprint, X } from '@lucide/vue'
import type { Evidence } from '../../investigations/events'

const props = defineProps<{ item?: Evidence }>()
const emit = defineEmits<{ close: [] }>()
const dialog = ref<HTMLDialogElement>()
const sourceUrl = computed(() => {
  try {
    const url = new URL(props.item?.uri || '')
    return url.protocol === 'https:' && !url.username && !url.password ? url.href : undefined
  } catch {
    return undefined
  }
})
watch(() => props.item, async item => {
  await nextTick()
  if (item && !dialog.value?.open) dialog.value?.showModal()
  else if (!item && dialog.value?.open) dialog.value.close()
})
</script>

<template>
  <dialog ref="dialog" class="evidence-drawer" aria-labelledby="evidence-title" @close="emit('close')">
    <template v-if="item">
      <header class="panel-header">
        <div class="panel-title"><span class="icon-tile"><Fingerprint :size="18" /></span>
          <div><h2 id="evidence-title">Evidence record</h2><p>{{ item.source.toUpperCase() }}</p></div>
        </div>
        <button class="icon-button" type="button" autofocus aria-label="Close evidence" @click="dialog?.close()"><X :size="19" /></button>
      </header>
      <dl class="evidence-fields">
        <dt>Source record</dt><dd>{{ item.source_record_id }}</dd>
        <dt>Source date</dt><dd>{{ item.source_date }}</dd>
        <dt>Retrieved</dt><dd>{{ item.retrieved_at }}</dd>
        <dt>License</dt><dd>{{ item.license }}</dd>
        <dt>Evidence ID</dt><dd>{{ item.evidence_id }}</dd>
        <dt>Payload SHA-256</dt><dd>{{ item.checksum }}</dd>
      </dl>
      <a v-if="sourceUrl" :href="sourceUrl" target="_blank" rel="noopener noreferrer" class="source-link">Open source <ExternalLink :size="15" /></a>
    </template>
  </dialog>
</template>
