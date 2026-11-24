import assert from 'node:assert/strict'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { createServer } from 'node:http'
import { open, readFile } from 'node:fs/promises'
import { chromium } from '@playwright/test'
import { decodeInvestigation } from '../.test-dist/stream.js'

const fixturePath = process.argv[2]
assert(fixturePath)
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'))
const cursor = fixturePath.replace('fixture.json', 'validation-calls.log')
let total = 0
try {
  total = (await readFile(cursor, 'utf8')).trim().split('\n').filter(Boolean).length
} catch (error) {
  if (error.code !== 'ENOENT') throw error
}

const callback = 'http://localhost:3000/auth/callback'
async function tokens(browser, credentials) {
  const context = await browser.newContext()
  try {
    const page = await context.newPage()
    const verifier = randomBytes(48).toString('base64url')
    const state = randomUUID()
    const authorize = new URL('/oauth2/authorize', fixture.domain)
    authorize.search = new URLSearchParams({
      client_id: fixture.client,
      response_type: 'code',
      scope: 'openid',
      redirect_uri: callback,
      state,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
    }).toString()
    await page.goto(authorize.href, { waitUntil: 'domcontentloaded', timeout: 25_000 })
    await page.locator('input[name="username"]:visible').fill(credentials.username)
    await page.locator('input[name="password"]:visible').fill(credentials.password)
    const form = page.locator('form').filter({ has: page.locator('input[name="username"]:visible') })
    await form.locator('input[type="submit"]:visible, button[type="submit"]:visible').first().click()
    try {
      await page.waitForURL(url => url.origin + url.pathname === callback, {
        waitUntil: 'domcontentloaded', timeout: 25_000,
      })
    } catch (error) {
      const alerts = await page.locator('.errorMessage:visible, [role="alert"]:visible').allTextContents()
      console.error(JSON.stringify({ oauth_path: new URL(page.url()).pathname, alerts }))
      throw error
    }
    const redirected = new URL(page.url())
    assert.equal(redirected.searchParams.get('state'), state)
    assert(redirected.searchParams.get('code'))
    const response = await fetch(new URL('/oauth2/token', fixture.domain), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: fixture.client, grant_type: 'authorization_code', redirect_uri: callback,
        code: redirected.searchParams.get('code'), code_verifier: verifier,
      }),
      signal: AbortSignal.timeout(10_000),
    })
    assert.equal(response.status, 200)
    const issued = await response.json()
    assert(issued.access_token && issued.id_token)
    return issued
  } finally { await context.close() }
}

const receiver = createServer((_request, response) => {
  response.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' })
  response.end('OAuth callback ready.')
})
await new Promise((resolve, reject) => receiver.once('error', reject).listen(3000, 'localhost', resolve))
const browser = await chromium.launch()
let member, peer, foreign
try {
  member = await tokens(browser, fixture.users.member)
  peer = await tokens(browser, fixture.users.peer)
  foreign = await tokens(browser, fixture.users.foreign)
} finally {
  await browser.close()
  receiver.close()
}

async function invoke(label, body, token, key, last) {
  assert(total < 20, 'AgentCore validation reached 20 admitted HTTP attempts')
  total += 1
  const log = await open(cursor, 'a', 0o600)
  try { await log.appendFile(label + '\n') } finally { await log.close() }
  const headers = new Headers({
    'Content-Type': 'application/json',
    Accept: body.action === 'cancel' ? 'application/json' : 'text/event-stream',
    'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id': randomUUID(),
  })
  if (token) headers.set('Authorization', 'Bearer ' + token)
  if (key) headers.set('Idempotency-Key', key)
  if (last) headers.set('Last-Event-ID', String(last))
  const response = await fetch(fixture.runtime, {
    method: 'POST', headers, body: JSON.stringify(body), redirect: 'error',
    signal: AbortSignal.timeout(75_000),
  })
  console.log(JSON.stringify({ operation: label, status: response.status, contentType: response.headers.get('content-type') }))
  return response
}

async function expected(response, statuses) {
  if (statuses.includes(response.status)) {
    await response.body?.cancel()
    return
  }
  const body = await response.text()
  if (response.status === 424) {
    const message = JSON.parse(body).message
    if (statuses.some(status => message?.includes('Received error (' + status + ') from runtime'))) return
  }
  throw new Error(`HTTP ${response.status} ${body.slice(0, 350)}`)
}

const request = {
  question: 'Prioritize known exploited vulnerabilities',
  scope: 'global',
  snapshot_id: fixture.snapshot,
}
await expected(await invoke('no-token', request), [401, 403])
await expected(await invoke('id-token', request, member.id_token), [401, 403])
await expected(await invoke('wrong-workspace', request, foreign.access_token, randomUUID()), [403])

const key = randomUUID()
const started = performance.now()
const response = await invoke('member-investigation', request, member.access_token, key)
if (!response.ok) await expected(response, [200])
let first
const events = []
for await (const event of decodeInvestigation(response.body)) {
  first ??= performance.now() - started
  events.push(event)
}
const elapsed = performance.now() - started
const report = events.find(event => event.type === 'report.completed')?.payload
const done = events.at(-1)
if (!report) console.error(JSON.stringify({ events }))
assert(report && report.snapshot_id === fixture.snapshot)
assert.equal(report.analysis_mode, 'bedrock')
assert(report.usage.length && report.claims.length)
const evidence = new Set(events.filter(event => event.type === 'evidence.added')
  .flatMap(event => event.payload.items.map(item => item.evidence_id)))
assert(report.claims.every(claim => claim.evidence_ids.every(id => evidence.has(id))))
assert.equal(done.payload.status, 'completed')
assert(events.some(event => event.type === 'ui.filters.proposed'))
const replay = await invoke('member-replay-cross-session', request, member.access_token, key, 1)
if (!replay.ok) await expected(replay, [200])
const replayed = []
for await (const event of decodeInvestigation(replay.body, 1)) replayed.push(event)
assert.deepEqual(replayed, events.slice(1))
const ownInvestigation = events[0].investigation_id
await expected(await invoke('same-workspace-peer', {
  action: 'cancel', investigation_id: ownInvestigation,
}, peer.access_token), [404])

const running = await invoke('cancel-target', request, member.access_token, randomUUID())
if (!running.ok) await expected(running, [200])
const sequence = []
for await (const event of decodeInvestigation(running.body)) {
  sequence.push(event)
  if (event.seq === 1) {
    const cancelled = await invoke('owner-cancel', {
      action: 'cancel', investigation_id: event.investigation_id,
    }, member.access_token)
    if (!cancelled.ok) await expected(cancelled, [200])
    assert.equal((await cancelled.json()).status, 'cancelled')
  }
}
assert.equal(sequence.filter(event => event.type === 'done').length, 1)
assert.equal(sequence.at(-1).payload.status, 'cancelled')
console.log(JSON.stringify({
  event: 'agentcore.smoke', events: events.length, claims: report.claims.length,
  citedIds: evidence.size, first_event_ms: +first.toFixed(2), complete_ms: +elapsed.toFixed(2),
  mode: report.analysis_mode, usage: report.usage,
  replay: replayed.length, cancellation: sequence.at(-1).payload.status, calls: total,
}))
