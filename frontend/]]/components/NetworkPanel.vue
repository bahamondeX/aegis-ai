<script setup lang="ts">
import type { Core, ElementDefinition, Position } from 'cytoscape'
import { Crosshair, GitFork, Minus, Plus, RotateCcw } from '@lucide/vue'
import type { Edge } from '../../investigations/events'

const props = defineProps<{ edges: Edge[] }>()
const emit = defineEmits<{ inspect: [id: string]; filter: [id: string]; detail: [id: string] }>()
const container = ref<HTMLElement>()
const selected = ref('')
const hasError = ref(false)
const chosen = computed(() => props.edges.find(row => row.evidence_id + row.target_id === selected.value))
const displayed = computed(() => {
  const counts = new Map<string, number>()
  for (const row of props.edges) counts.set(row.cve_id, (counts.get(row.cve_id) ?? 0) + 1)
  const sources = [...counts].sort((first, second) => second[1] - first[1]).slice(0, 4).map(([id]) => id)
  return sources.flatMap(source => props.edges.filter(row => row.cve_id === source).slice(0, 9))
})
let cy: Core | undefined
let disposed = false
let resize: ResizeObserver | undefined

function fit() { cy?.fit(undefined, 24) }
function zoom(scale: number) {
  if (!cy) return
  cy.zoom({ level: cy.zoom() * scale, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } })
}
function focus() {
  if (!cy || !chosen.value) return
  cy.elements().unselect()
  const node = cy.getElementById(chosen.value.target_id)
  node.select()
  cy.center(node)
}
function draw() {
  if (!cy) return
  selected.value = ''
  const positions: Record<string, Position> = {}
  const elements: ElementDefinition[] = []
  const roots = [...new Set(displayed.value.map(row => row.cve_id))]
  const targets = new Set<string>()
  for (const [i, root] of roots.entries()) {
    const center = { x: (i % 2) * 325 + 170, y: Math.floor(i / 2) * 205 + 115 }
    positions[root] = center
    elements.push({
      group: 'nodes', data: { id: root, label: root, kind: 'cve' },
    })
    const rows = displayed.value.filter(row => row.cve_id === root)
    for (const [index, row] of rows.entries()) {
      const cwe = row.target_id.startsWith('CWE-')
      const target = row.target_id
      if (!targets.has(target)) {
        targets.add(target)
        const angle = -Math.PI * 0.54 + index * 2 * Math.PI / rows.length
        positions[target] = { x: center.x + 114 * Math.cos(angle), y: center.y + 75 * Math.sin(angle) }
        elements.push({
          group: 'nodes',
          data: { id: target, label: row.target_label.slice(0, 28), kind: cwe ? 'cwe' : 'product' },
        })
      }
      elements.push({
        group: 'edges', data: { id: root + ':' + index, source: root, target, choice: row.evidence_id + target },
      })
    }
  }
  cy.elements().remove()
  cy.add(elements)
  cy.layout({ name: 'preset', positions, fit: true, padding: 26 }).run()
}
onMounted(async () => {
  try {
    const { default: cytoscape } = await import('cytoscape')
    if (!container.value || disposed) return
    cy = cytoscape({
      container: container.value,
      elements: [],
      minZoom: 0.15, maxZoom: 3, wheelSensitivity: 0.22,
      boxSelectionEnabled: false,
      style: [
        { selector: 'node', style: {
          label: 'data(label)', color: '#aec5d0', 'font-size': 11, 'font-family': 'IBM Plex Mono',
          'text-valign': 'bottom', 'text-margin-y': 5, width: 12, height: 12,
          'background-color': '#49aeb8', 'border-width': 1, 'border-color': '#86d5df',
        } },
        { selector: 'node[kind = "cve"]', style: {
          width: 34, height: 34, 'background-color': '#126656', 'border-width': 2,
          'border-color': '#43e2bd', color: '#b4f7e4', 'font-size': 13,
          'text-background-color': '#0b1420', 'text-background-opacity': 0.85,
          'text-background-padding': '2px',
        } },
        { selector: 'node[kind = "cwe"]', style: {
          shape: 'diamond', 'background-color': '#f2b963', 'border-color': '#ffdaa1',
        } },
        { selector: 'edge', style: {
          width: 1.1, 'line-color': '#315462', opacity: 0.78, 'curve-style': 'bezier',
        } },
        { selector: ':selected', style: { 'border-color': '#ffffff', 'border-width': 3 } },
      ],
    })
    cy.on('tap', 'edge', (event) => {
      const choice: unknown = event.target.data('choice')
      if (typeof choice === 'string') selected.value = choice
    })
    cy.on('tap', 'node[kind = "cve"]', (event) => {
      const id: unknown = event.target.id()
      if (typeof id === 'string') emit('detail', id)
    })
    resize = new ResizeObserver(() => { cy?.resize(); fit() })
    resize.observe(container.value)
    draw()
  } catch {
    hasError.value = true
  }
})
watch(displayed, draw)
onUnmounted(() => {
  disposed = true
  resize?.disconnect()
  cy?.destroy()
})
</script>

<template>
  <section id="relationships" class="panel network-panel" aria-labelledby="network-title">
    <header class="panel-header">
      <div class="panel-title">
        <span class="icon-tile"><GitFork :size="18" aria-hidden="true" /></span>
        <div><h2 id="network-title">Relationship network</h2><p>CVE, product and weakness links</p></div>
      </div>
      <div class="map-buttons" aria-label="Graph controls">
        <button title="Zoom out" aria-label="Zoom out" @click="zoom(0.8)"><Minus :size="15" /></button>
        <button title="Zoom in" aria-label="Zoom in" @click="zoom(1.25)"><Plus :size="15" /></button>
        <button title="Fit graph" aria-label="Fit graph" @click="fit"><RotateCcw :size="15" /></button>
      </div>
    </header>
    <div class="network-stage">
      <span v-if="displayed.length" class="viewport-chip"><Crosshair :size="14" aria-hidden="true" /> {{ displayed.length }} LINKS SHOWN</span>
      <div ref="container" class="visual-surface" aria-label="Interactive evidence relationship graph" />
      <p v-if="!displayed.length || hasError" class="visual-fallback">
        {{ hasError ? 'Graph canvas unavailable. Browse links below.' : 'No relationships match these filters.' }}
      </p>
    </div>
    <footer class="network-controls">
      <div class="legend" aria-label="Node legend">
        <span><i class="cve" /> CVE</span><span><i class="product" /> Product</span><span><i class="cwe" /> CWE</span>
      </div>
      <label v-if="displayed.length" class="graph-select">
        <span class="sr-only">Inspect a relationship</span>
        <select v-model="selected" @change="focus">
          <option value="">Inspect relationship</option>
          <option
v-for="row in displayed" :key="row.evidence_id + row.target_id + row.cve_id"
                  :value="row.evidence_id + row.target_id">{{ row.cve_id }} · {{ row.target_label }}</option>
        </select>
      </label>
      <div v-if="chosen" class="cve-source-actions">
        <button type="button" class="text-button" @click="emit('detail', chosen.cve_id)">Open CVE detail</button>
        <button type="button" class="text-button" @click="emit('filter', chosen.cve_id)">Filter workspace to CVE</button>
      </div>
      <UButton v-if="chosen" size="xs" variant="soft" @click="emit('inspect', chosen.evidence_id)">Evidence</UButton>
    </footer>
  </section>
</template>
