import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { expect, test, type Page } from '@playwright/test'

const target = process.env.AEGIS_BROWSER_URL
const fixture = process.env.AEGIS_BROWSER_HOSTED_FIXTURE
const evidence = process.env.AEGIS_BROWSER_EVIDENCE || '../data/evidence/final'

interface Credentials { username: string, password: string }
interface HostedFixture {
  hosted: boolean
  runtime: string
  snapshot: string
  users: { member: Credentials, peer: Credentials, foreign: Credentials }
}
interface Frame {
  investigation_id: string
  seq: number
  type: string
  payload: { status?: string, analysis_mode?: string, snapshot_id?: string }
}

function decode(body: string): Frame[] {
  return body.split('\n').filter(line => line.startsWith('data: ')).map(line => JSON.parse(line.slice(6)) as Frame)
}

async function login(page: Page, account: Credentials): Promise<string> {
  await page.goto('/')
  const authorization = page.waitForRequest(r => new URL(r.url()).pathname === '/oauth2/authorize')
  const accountRequest = page.waitForRequest(r => r.url().endsWith('/api/aegis/v1/account'))
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  const authorize = new URL((await authorization).url())
  expect(authorize.searchParams.get('code_challenge_method')).toBe('S256')
  expect(authorize.searchParams.get('redirect_uri')).toBe(target + '/auth/callback')
  const form = page.locator('form').filter({ has: page.locator('input[name="username"]:visible') })
  await form.locator('input[name="username"]:visible').fill(account.username)
  await form.locator('input[name="password"]:visible').fill(account.password)
  await form.locator('input[type="submit"]:visible, button[type="submit"]:visible').first().click()
  const bearer = (await (await accountRequest).allHeaders()).authorization
  if (!bearer?.startsWith('Bearer ')) throw new Error('OAuth did not supply an access token')
  const stored = await page.evaluate(() => [
    ...Object.values(localStorage), ...Object.values(sessionStorage),
  ].join('\n'))
  expect(/"access_token"|"refresh_token"/.test(stored)).toBe(false)
  return bearer
}

test('CloudFront serves HTTPS and excludes unapproved users from analytics and administration', async ({ page, request, browser }) => {
  test.skip(!target?.startsWith('https://'), 'The hosted acceptance requires the actual CloudFront URL.')
  const home = await page.goto('/')
  expect(home?.status()).toBe(200)
  expect(home?.headers()['strict-transport-security']).toContain('max-age=')
  await expect(page.getByRole('button', { name: 'Register with email' })).toBeVisible()
  await page.screenshot({ path: join(evidence, 'production-sign-in.png') })
  await page.goto('/admin')
  await expect(page.getByRole('heading', { name: 'Administrator access required' })).toBeVisible()
  expect((await request.get('/api/aegis/v1/coverage')).status()).toBe(401)
  expect((await request.get('/api/aegis/v1/admin/users')).status()).toBe(401)
  if (fixture) {
    const scoped = JSON.parse(await readFile(fixture, 'utf8')) as HostedFixture
    if (!scoped.hosted) throw new Error('A hosted validation fixture is required')
    const context = await browser.newContext({ baseURL: target })
    try {
      const pendingPage = await context.newPage()
      const bearer = await login(pendingPage, scoped.users.foreign)
      await expect(pendingPage.getByRole('heading', { name: 'Approval pending' })).toBeVisible()
      expect((await request.get('/api/aegis/v1/coverage', { headers: { Authorization: bearer } })).status()).toBe(403)
      expect((await request.get('/api/aegis/v1/admin/users', { headers: { Authorization: bearer } })).status()).toBe(403)
      expect((await request.get('/api/aegis/mcp', { headers: { Authorization: bearer } })).status()).toBe(404)
      const payload = { snapshot_id: scoped.snapshot, question: 'Prioritize known exploited vulnerabilities' }
      const runtime = await request.post(scoped.runtime, {
        headers: {
          Authorization: bearer,
          'Idempotency-Key': crypto.randomUUID(),
          'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id': crypto.randomUUID(),
        },
        data: payload,
      })
      expect([403, 424]).toContain(runtime.status())
      if (runtime.status() === 424) expect(await runtime.text()).toMatch(/403|approval_required/)
      await pendingPage.screenshot({ path: join(evidence, 'production-pending.png'), mask: [pendingPage.getByText(scoped.users.foreign.username + '@example.invalid')] })
    } finally { await context.close() }
  }
})

test('approved browser reads one snapshot and streams live evidence-backed mitigation', async ({ page, request, browser }) => {
  test.skip(!target?.startsWith('https://') || !fixture, 'The hosted journey requires actual AWS and temporary identities.')
  test.setTimeout(180_000)
  const scoped = JSON.parse(await readFile(fixture!, 'utf8')) as HostedFixture
  if (!scoped.hosted) throw new Error('A hosted validation fixture is required')
  const bearer = await login(page, scoped.users.member)
  const headers = { Authorization: bearer }
  await expect(page.getByRole('heading', { name: 'Threat command center.' })).toBeVisible()
  await expect(page.getByText('Exposure coverage unavailable')).toBeVisible()
  const context = await request.get('/api/aegis/v1/map?country_iso2=CA', { headers })
  expect(context.status()).toBe(200)
  const map = await context.json()
  expect(map.snapshot_id).toBe(scoped.snapshot)
  expect(map.network.state).toBe('available')
  expect(map.data).toEqual([])
  const peru = await request.get('/api/aegis/v1/map?country_iso2=PE', { headers })
  expect(peru.status()).toBe(200)
  const peruMap = await peru.json()
  expect(peruMap.network.state).toBe('unavailable')
  expect(peruMap.data).toEqual([])
  const source = await request.get('/api/aegis/v1/coverage', { headers })
  expect((await source.json()).snapshot_id).toBe(scoped.snapshot)
  expect((await request.get('/api/aegis/v1/admin/users', { headers })).status()).toBe(403)
  const relationship = page.getByLabel('Inspect a relationship')
  await expect(relationship).toBeVisible({ timeout: 40_000 })
  await relationship.selectOption({ index: 1 })
  const card = page.getByRole('button', { name: 'Open CVE detail', exact: true })
  await expect(card).toBeVisible()
  await page.screenshot({ path: join(evidence, 'production-command-center.png') })
  await card.click()
  await expect(page.getByRole('button', { name: 'How to mitigate' })).toBeVisible()
  await page.screenshot({ path: join(evidence, 'production-cve-detail.png') })
  const streaming = page.waitForResponse(r =>
    r.request().method() === 'POST' && r.url().endsWith('/api/aegis/v1/investigations'))
  const startedAt = performance.now()
  await page.getByRole('button', { name: 'How to mitigate' }).click()
  const response = await streaming
  const firstHeaderMs = performance.now() - startedAt
  expect(response.status()).toBe(200)
  expect(response.headers()['content-type']).toContain('text/event-stream')
  await expect(page.getByLabel('Investigation progress')).toBeVisible({ timeout: 60_000 })
  const firstProgressMs = performance.now() - startedAt
  await expect(page.getByRole('heading', { name: 'Verified findings' })).toBeVisible({ timeout: 68_000 })
  const browserCompletionMs = performance.now() - startedAt
  expect(browserCompletionMs - firstProgressMs).toBeGreaterThan(100)
  const frames = decode(await response.text())
  const terminal = frames.filter(frame => frame.type === 'done')
  expect(frames.map(frame => frame.seq)).toEqual(frames.map((_, index) => index + 1))
  expect(terminal).toHaveLength(1)
  expect(terminal[0]?.payload.status).toBe('completed')
  const report = frames.find(frame => frame.type === 'report.completed')
  expect(report?.payload.analysis_mode).toBe('bedrock')
  expect(report?.payload.snapshot_id).toBe(scoped.snapshot)
  await writeFile(join(evidence, 'production-mitigation.json'), JSON.stringify({
    firstHeaderMs, firstProgressMs, browserCompletionMs, frames, countryExposure: [map, peruMap],
  }))
  await page.getByRole('article', { name: 'Investigation report' }).scrollIntoViewIfNeeded()
  await page.screenshot({ path: join(evidence, 'production-mitigation.png') })

  const initial = response.request()
  const start = await initial.allHeaders()
  const replay = await request.post('/api/aegis/v1/investigations', {
    headers: { ...headers, 'Idempotency-Key': start['idempotency-key'] ?? '', 'Last-Event-ID': '2' },
    data: initial.postDataJSON(),
  })
  expect(replay.status()).toBe(200)
  expect(decode(await replay.text())).toEqual(frames.slice(2))
  const peerContext = await browser.newContext({ baseURL: target })
  try {
    const peer = await login(await peerContext.newPage(), scoped.users.peer)
    const denied = await request.post(scoped.runtime, {
      headers: {
        Authorization: peer, 'Idempotency-Key': start['idempotency-key'] ?? '',
        'Last-Event-ID': '2', 'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id': crypto.randomUUID(),
      },
      data: initial.postDataJSON(),
    })
    expect([409, 424]).toContain(denied.status())
    if (denied.status() === 424) expect(await denied.text()).toMatch(/409|invalid_cursor/)
  } finally { await peerContext.close() }

})

test('hosted cancellation and logout invalidate the active session', async ({ page, request, browser }) => {
  test.skip(!target?.startsWith('https://') || !fixture, 'The hosted journey requires actual AWS and temporary identities.')
  test.setTimeout(180_000)
  const scoped = JSON.parse(await readFile(fixture!, 'utf8')) as HostedFixture
  if (!scoped.hosted) throw new Error('A hosted validation fixture is required')
  const bearer = await login(page, scoped.users.member)
  const headers = { Authorization: bearer }
  await expect(page.getByText('Exposure coverage unavailable')).toBeVisible()
  // Warm two independent Lambda executions before the cancellation race.
  const warmed = await Promise.all([
    request.get('/api/aegis/v1/kpis', { headers, timeout: 65_000 }),
    request.get('/api/aegis/v1/cves?limit=1', { headers, timeout: 65_000 }),
  ])
  expect(warmed.map(response => response.status())).toEqual([200, 200])
  const cancellation = page.evaluate(async ({ bearer, snapshot }) => {
    const key = crypto.randomUUID()
    const base = '/api/aegis/v1/investigations'
    const headers = { Authorization: bearer, 'Idempotency-Key': key, 'Content-Type': 'application/json' }
    const signal = AbortSignal.timeout(65_000)
    const response = await fetch(base, {
      method: 'POST', headers, signal,
      body: JSON.stringify({ snapshot_id: snapshot, question: 'Prioritize known exploited vulnerabilities' }),
    })
    if (!response.ok || !response.body) throw new Error('Cancellation fixture could not start')
    const reader = response.body.pipeThrough(new TextDecoderStream()).getReader()
    let pending = ''
    let status = 0
    const events: Frame[] = []
    try {
      while (true) {
        const item = await reader.read()
        if (item.done) break
        pending += item.value
        const lines = pending.split('\n')
        pending = lines.pop() ?? ''
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          const frame = JSON.parse(line.slice(6)) as Frame
          events.push(frame)
          if (!status && frame.type === 'investigation.started') {
            const request = await fetch(base + '/' + frame.investigation_id + '/cancel', {
              method: 'POST', headers, signal,
            })
            status = request.status
          }
        }
      }
    } finally { await reader.cancel() }
    return { status, terminal: events.filter(event => event.type === 'done'), key }
  }, { bearer, snapshot: scoped.snapshot })
  const stopped = await cancellation
  expect(stopped.status).toBe(200)
  expect(stopped.terminal).toHaveLength(1)
  expect(stopped.terminal[0]?.payload.status).toBe('cancelled')
  const peerContext = await browser.newContext({ baseURL: target })
  try {
    const peer = await login(await peerContext.newPage(), scoped.users.peer)
    const denied = await request.post(scoped.runtime, {
      headers: {
        Authorization: peer, 'Idempotency-Key': stopped.key,
        'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id': crypto.randomUUID(),
      },
      data: { action: 'cancel', investigation_id: stopped.terminal[0]?.investigation_id },
    })
    expect([404, 424]).toContain(denied.status())
    if (denied.status() === 424) expect(await denied.text()).toMatch(/404|not_found/)
  } finally { await peerContext.close() }
  const logout = page.waitForResponse(response => response.url().endsWith('/api/aegis/v1/account/logout'))
  await page.getByRole('button', { name: 'Sign out', exact: true }).click()
  expect((await logout).status()).toBe(204)
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible()
  expect((await request.get('/api/aegis/v1/coverage', { headers })).status()).toBe(401)
  await writeFile(join(evidence, 'production-session-checks.json'), JSON.stringify({
    terminalStatus: stopped.terminal[0]?.payload.status, terminalCount: stopped.terminal.length,
    cancellationStatus: stopped.status, peerCancellationDenied: true, logoutRevokedAccess: true,
  }))
})
