import assert from 'node:assert/strict'
import test from 'node:test'

import { decodeInvestigation } from '../.test-dist/stream.js'
import { acceptProposal, begin, editFilters, receive } from '../.test-dist/view.js'

// Synthetic event fixtures exercise only the isolated stream and state tests.
const snapshot = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
const identifier = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const trace = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const stamp = '2026-11-21T00:00:00Z'
const event = (type, seq, payload) => ({
  version: 1, investigation_id: identifier, seq, timestamp: stamp, type, payload,
})
const started = event('investigation.started', 1, { snapshot_id: snapshot, trace_id: trace })
const proposal = event('ui.filters.proposed', 2, {
  command: 'propose_filters', snapshot_id: snapshot, filters: { kev_only: true, limit: 3 },
})
const done = event('done', 3, { status: 'completed' })

const frame = ({ type, seq, ...rest }) =>
  `id: ${seq}\r\nevent: ${type}\r\ndata: ${JSON.stringify({ type, seq, ...rest })}\r\n\r\n`

async function events(text, after = 0) {
  const bytes = new TextEncoder().encode(text)
  const stream = new ReadableStream({
    start(controller) {
      for (let index = 0; index < bytes.length; index += 11) {
        controller.enqueue(bytes.slice(index, index + 11))
      }
      controller.close()
    },
  })
  const results = []
  for await (const item of decodeInvestigation(stream, after)) results.push(item)
  return results
}

test('split SSE stream and heartbeats preserve event order and cursor replay', async () => {
  assert.deepEqual(
    await events(frame(started) + ': heartbeat\r\n\r\n' + frame(proposal) + frame(done)),
    [started, proposal, done],
  )
  assert.deepEqual(await events(frame(proposal) + frame(done), 1), [proposal, done])
})

test('reject events with invalid ordering, disagreement, or missing terminal', async () => {
  await assert.rejects(events(frame(started) + frame(done)), /Out-of-order/)
  await assert.rejects(events(frame(started) + frame(proposal)), /ended before done/)
  await assert.rejects(events(frame(started).replace('id: 1', 'id: 2')), /Invalid investigation/)
})

test('reject arbitrary commands, malformed filters and contradictory dates', async () => {
  for (const payload of [
    { ...proposal.payload, command: 'execute_javascript' },
    { ...proposal.payload, filters: { limit: 999 } },
    { ...proposal.payload, filters: { extra: 'unrecognized' } },
    { ...proposal.payload, filters: { date_from: '2026-12-01', date_to: '2026-11-01' } },
  ]) {
    await assert.rejects(
      events(frame(started) + frame({ ...proposal, payload }) + frame(done)),
      /Invalid/,
    )
  }
})

test('apply current proposal atomically and preserve later manual edits', () => {
  const initial = {
    generation: 0, snapshot, seq: 0, terminal: false, manualRevision: 0,
    startedAtRevision: 0, filters: { kev_only: false },
  }
  const active = receive(begin(initial, snapshot), 1, started)
  const pending = receive(active, 1, proposal)
  assert.deepEqual(pending.filters, initial.filters)
  assert.deepEqual(acceptProposal(pending).filters, proposal.payload.filters)

  const withEdit = editFilters(active, { country_iso2: 'PE' })
  assert.deepEqual(acceptProposal(receive(withEdit, 1, proposal)).filters, withEdit.filters)
  assert.equal(receive(active, 0, proposal), active)
  const foreign = { ...proposal, investigation_id: trace }
  assert.equal(receive(active, 1, foreign), active)
  const otherRelease = { ...proposal, payload: { ...proposal.payload, snapshot_id: trace } }
  assert.equal(receive(active, 1, otherRelease), active)
})
