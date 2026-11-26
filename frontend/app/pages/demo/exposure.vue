<script setup lang="ts">
import type { ShadowserverContext } from '../../../investigations/exposure'
import {
  demoCve, demoCves, demoDates, demoProjection, shadowserver,
} from '../../../investigations/shadowserver'

useHead({ title: 'Exposición a CVE · AEGIS' })

const country = ref('')
const day = ref(demoDates[0] ?? '')
const cve = ref('')
const projection = computed(() => demoProjection(day.value, cve.value))
const selected = shallowRef<{ id: string; geographic: ShadowserverContext }>()
const detail = computed(() => selected.value ? demoCve(selected.value.id) : undefined)
const dialog = ref<HTMLDialogElement>()

function chooseCountry(code: string) {
  dialog.value?.close()
  country.value = code
}

function openDetail(id: string, geographic: ShadowserverContext) {
  selected.value = { id, geographic }
  dialog.value?.showModal()
}
watch([day, cve], () => dialog.value?.close())
</script>

<template>
  <main class="exposure-demo">
    <header class="demo-header">
      <div>
        <p class="demo-brand"><AegisMark /> AEGIS</p>
        <h1>Globo de exposición a CVE</h1>
        <p>Muestra histórica de Shadowserver con cobertura parcial por país y día.</p>
      </div>
      <a class="text-button" href="/">Catálogo global de AEGIS</a>
    </header>
    <HistoricalExposurePanel
      :projection="projection"
      :country="country || undefined" @area="chooseCountry" @detail="openDetail"
    >
      <template #filters>
        <label>Fecha observada <input v-model="day" type="date" list="sample-dates"></label>
        <datalist id="sample-dates">
          <option v-for="date in demoDates" :key="date" :value="date" />
        </datalist>
        <label>CVE
          <select v-model="cve">
            <option value="">Todas en la muestra</option>
            <option v-for="id in demoCves" :key="id" :value="id">{{ id }}</option>
          </select>
        </label>
      </template>
    </HistoricalExposurePanel>
    <p class="demo-note">Los colores reflejan las CVE de la muestra del día seleccionado. La cobertura por país varía entre publicaciones.</p>
    <dialog ref="dialog" class="panel cve-detail" aria-label="Ficha CVE" @close="selected = undefined">
      <template v-if="detail && selected">
        <header>
          <h2>{{ detail.id }}</h2>
          <button type="button" class="text-button" @click="dialog?.close()">Cerrar</button>
        </header>
        <h3>Observación geográfica</h3>
        <ShadowserverObservation :context="selected.geographic" />
        <p><a :href="shadowserver.href" target="_blank" rel="noopener noreferrer">{{ shadowserver.label }}</a></p>
        <h3>Ficha global · {{ detail.product }}</h3>
        <p>{{ detail.description }}</p>
        <dl class="cve-facts">
          <div><dt>CVSS</dt><dd>{{ detail.cvss_score ?? 'Sin clasificación' }} · {{ detail.cvss_version }} · {{ detail.severity }} · {{ detail.cvss_source }}</dd></div>
        </dl>
        <p><a :href="detail.source_url" target="_blank" rel="noopener noreferrer">Ver ficha publicada en NVD</a></p>
        <p><a href="/">Abrir catálogo global de AEGIS</a></p>
      </template>
    </dialog>
  </main>
</template>

<style scoped>
.exposure-demo { max-width: 1050px; margin: auto; padding: clamp(16px, 4vw, 36px); color: #dce8f2; }
.demo-header { display: flex; gap: 16px; justify-content: space-between; flex-wrap: wrap; align-items: end; margin-bottom: 18px; }
.demo-brand { display: flex; align-items: center; gap: 8px; font-weight: 750; letter-spacing: .1em; }
.demo-brand :deep(svg) { width: 27px; height: 27px; }
.demo-header h1 { font-size: clamp(1.65rem, 5vw, 2.5rem); font-weight: 750; line-height: 1.13; margin: 6px 0; }
.demo-header p, .demo-note { color: #b7c8d9; margin: 0; }
.demo-note { margin-top: 10px; }
.exposure-demo :deep(.geo-stage) { height: clamp(285px, 49vh, 485px); }
.exposure-demo :deep(input[type="date"]) { color-scheme: dark; background: #23344a; border-radius: 4px; padding: .2rem .4rem; }
.exposure-demo a { color: #9de7da; text-decoration: underline; text-underline-offset: .25em; }
</style>
