<script setup lang="ts">
import { ArrowUp, Bot, Check, CircuitBoard, FileText, ListFilter, Square } from '@lucide/vue'
import { handoffSummary } from '../../investigations/geography'
import type { FilterProposal, Report } from '../../investigations/events'

interface Step { id: number; label: string; revision: number }
const props = defineProps<{
  ready: boolean; running: boolean; steps: Step[]; report?: Report;
  mitigationCve: string; mitigationCountry?: string | null;
  proposal?: FilterProposal; error: string; applied: number;
}>()
const emits = defineEmits<{
  start: [question: string, scope?: 'global' | 'regional'];
  stop: []; apply: []; inspect: [id: string];
}>()
const question = ref('')
const helpOpen = ref(false)
const draft = ref('')
watch(() => props.report, () => {
  helpOpen.value = false
  draft.value = ''
})
function requestHelp() {
  if (!props.report || !props.mitigationCve) return
  draft.value = handoffSummary(props.mitigationCve, props.report, props.mitigationCountry)
  helpOpen.value = true
}
const scope = ref<'' | 'global' | 'regional'>('')
function submit() {
  const value = question.value.trim()
  if (value) emits('start', value, scope.value || undefined)
}
const suggestions = [
  'Prioritize known exploited vulnerabilities',
  'What evidence is available for South America?',
]
</script>

<template>
  <section id="investigations" class="panel investigation-panel" aria-labelledby="investigation-title">
    <header class="panel-header">
      <div class="panel-title">
        <span class="icon-tile"><Bot :size="18" aria-hidden="true" /></span>
        <div><h2 id="investigation-title" tabindex="-1">Investigation workspace</h2><p>Evidence-backed analyst</p></div>
      </div>
      <span class="small-count"><span class="status-dot" :class="{ pulse: running }" /> {{ running ? 'RUNNING' : 'READY' }}</span>
    </header>
    <div class="investigation-body">
      <div v-if="!steps.length && !report" class="agent-welcome">
        <span class="agent-icon"><CircuitBoard :size="26" aria-hidden="true" /></span>
        <h3>Investigate your current view</h3>
        <p>Run an investigation to review prioritized findings, trace sources and apply suggested filters.</p>
        <div class="suggestions">
          <button
v-for="suggestion in suggestions" :key="suggestion" type="button" :disabled="!ready"
                  @click="question = suggestion; submit()">{{ suggestion }}</button>
        </div>
      </div>
      <ol v-if="steps.length" class="steps" aria-label="Investigation progress" aria-live="polite">
        <li v-for="step in steps" :key="step.id">
          <Check :size="15" aria-hidden="true" /> <span>{{ step.label }}</span>
          <small v-if="step.revision">Revision</small>
        </li>
      </ol>
      <div v-if="proposal" class="filter-proposal">
        <ListFilter :size="16" aria-hidden="true" />
        <div><strong>Suggested filters</strong><p>{{ proposal.filters.limit ?? 50 }} rows per view</p></div>
        <UButton size="xs" variant="soft" @click="emits('apply')">Apply</UButton>
      </div>
      <p v-if="applied" class="applied-status" role="status">Filters applied to the workspace</p>
      <article v-if="report" class="investigation-report" aria-label="Investigation report">
        <div class="report-heading"><FileText :size="16" aria-hidden="true" /> <h3>Verified findings</h3></div>
        <p class="report-mode">{{ { bedrock: 'Bedrock analysis', fallback: 'Grounded fallback', deterministic: 'Deterministic analysis' }[report.analysis_mode] }}</p>
        <ul v-if="report.claims.length">
          <li v-for="claim in report.claims" :key="claim.key">
            <p>{{ claim.text }}</p>
            <button v-for="id in claim.evidence_ids" :key="id" type="button" @click="emits('inspect', id)">Evidence {{ id.slice(0, 7) }}</button>
          </li>
        </ul>
        <p>{{ report.geographic_note }}</p>
        <p v-for="recommendation in report.recommendations" :key="recommendation">{{ recommendation }}</p>
        <UButton v-if="mitigationCve" type="button" variant="soft" @click="requestHelp">Request help</UButton>
        <div v-if="helpOpen" class="handoff">
          <label for="help-summary">SOC / CSIRT handoff draft</label>
          <textarea id="help-summary" v-model="draft" rows="9" maxlength="12000" />
          <p>Review and edit this draft before sharing it through your organization’s approved channel. FIRST maintains a CSIRT directory.</p>
        </div>
      </article>
      <p v-if="error" class="form-error" role="alert">{{ error }}</p>
    </div>
    <form class="investigation-form" @submit.prevent="submit">
      <label for="investigation-question" class="sr-only">Investigation question</label>
      <input
id="investigation-question" v-model="question" maxlength="600" :disabled="!ready"
             placeholder="Ask about the current scope">
      <select v-model="scope" aria-label="Investigation scope" :disabled="!ready || running">
        <option value="">Current scope</option>
        <option value="global">Global</option>
        <option value="regional">Regional</option>
      </select>
      <UButton v-if="running" type="button" color="warning" variant="soft" aria-label="Cancel investigation" @click="emits('stop')">
        <Square :size="15" aria-hidden="true" />
      </UButton>
      <UButton v-else class="primary-action" type="submit" :disabled="!question.trim() || !ready" aria-label="Run investigation">
        <ArrowUp :size="17" aria-hidden="true" />
      </UButton>
    </form>
  </section>
</template>
