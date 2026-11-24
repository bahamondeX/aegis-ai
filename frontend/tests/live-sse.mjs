import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { performance } from 'node:perf_hooks'

import { readInvestigation } from '../.test-dist/stream.js'
import { acceptProposal, begin, receive } from '../.test-dist/view.js'

const [base, tokenFile] = process.argv.slice(2)
assert(base && tokenFile)
const health = await fetch(new URL('/health', base))
assert(health.ok)
const { snapshot_id: snapshot } = await health.json()
const token = (await readFile(tokenFile, 'utf8')).trim()
const options = {
  endpoint: new URL('/v1/investigations', base),
  token,
  key: randomUUID(),
  request: { question: 'Rank vulnerabilities', scope: 'global', snapshot_id: snapshot },
}
let view = begin({
  generation: 0, snapshot, seq: 0, terminal: false,
  manualRevision: 0, startedAtRevision: 0, filters: {},
}, snapshot)
let first = 0
let count = 0
let report
const started = performance.now()
for await (const item of readInvestigation(options)) {
  first ||= performance.now() - started
  count += 1
  view = receive(view, 1, item)
  if (item.type === 'report.completed') report = item.payload
}
assert(view.terminal && view.proposal && view.proposedAnalytics)
assert(report?.claims.length > 0 && report.snapshot_id === snapshot)
const applied = acceptProposal(view)
assert.deepEqual(applied.filters, view.proposal.filters)
assert.deepEqual(applied.analytics?.filters, applied.filters)
console.log(JSON.stringify({
  events: count, snapshot, first_event_ms: +first.toFixed(2),
  complete_ms: +(performance.now() - started).toFixed(2), proposed_limit: view.proposal.filters.limit,
}))
