import { createHmac, randomUUID } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { expect, test, type Page } from '@playwright/test'

const target = process.env.AEGIS_BROWSER_URL
const fixture = process.env.AEGIS_BROWSER_HOSTED_FIXTURE
const v2 = process.env.AEGIS_BROWSER_EXPECT_V2 === '1'
const historicalAgent = process.env.AEGIS_BROWSER_EXPECT_HISTORY_AGENT === '1'
const authenticator = process.env.AEGIS_BROWSER_EXPECT_AUTHENTICATOR === '1'
const publicOnly = process.env.AEGIS_BROWSER_PUBLIC_ONLY === '1'
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
  if (authenticator) {
    await page.goto('/login')
    const accountRequest = page.waitForRequest(r => r.url().endsWith('/api/aegis/v1/account'))
    await page.getByLabel('Username').fill(account.username)
    await page.getByLabel('Password').fill(account.password)
    await page.getByRole('button', { name: 'Sign in', exact: true }).click()
    const bearer = (await (await accountRequest).allHeaders()).authorization
    if (!bearer?.startsWith('Bearer ')) throw new Error('Cognito did not supply an access token')
    return bearer
  }
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

test('Authenticator public entry point redirects the former admin page', async ({ page, request }) => {
  test.skip(!target?.startsWith('https://') || !authenticator)
  const home = await page.goto('/')
  expect(home?.status()).toBe(200)
  expect(home?.headers()['strict-transport-security']).toContain('max-age=')
  await expect(page.getByRole('heading', { name: 'Threat command center.' })).toBeVisible()
  expect(await page.evaluate(() => [...document.body.childNodes]
    .filter(node => node.nodeType === Node.TEXT_NODE)
    .map(node => node.textContent?.trim())
    .filter(Boolean))).toEqual([])
  await page.getByRole('link', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Sign in to AEGIS' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Register with email' })).toBeVisible()
  await page.screenshot({ path: join(evidence, 'login-desktop.png') })
  await page.setViewportSize({ width: 390, height: 844 })
  await expect(page.getByRole('button', { name: 'Continue with Google' })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390)
  await page.screenshot({ path: join(evidence, 'login-mobile.png') })
  const admin = await request.get('/admin', { maxRedirects: 0 })
  expect(admin.status()).toBe(302)
  expect(new URL(admin.headers().location!, target).pathname).toBe('/')
  expect((await request.get('/api/aegis/v1/admin/users')).status()).toBe(404)
  expect((await request.get('/api/aegis/v1/coverage')).status()).toBe(401)
  const google = page.waitForRequest(r => {
    const url = new URL(r.url())
    return r.isNavigationRequest() && url.hostname === 'accounts.google.com'
      && url.pathname === '/o/oauth2/v2/auth'
  })
  await page.getByRole('button', { name: 'Continue with Google' }).click()
  const redirect = new URL((await google).url()).searchParams.get('redirect_uri')
  expect(new URL(redirect!).pathname).toBe('/oauth2/idpresponse')
})

function authenticatorCode(key: string, step: number): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...key].map(value => alphabet.indexOf(value).toString(2).padStart(5, '0')).join('')
  const secret = Buffer.from(bits.match(/.{8}/g)!.map(value => Number.parseInt(value, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(step))
  const hash = createHmac('sha1', secret).update(counter).digest()
  return ((hash.readUInt32BE(hash.at(-1)! & 15) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0')
}

test('Authenticator pilot checks the hosted session and streams one pinned analysis', async ({ page, request, browser }) => {
  test.skip(!target?.startsWith('https://') || !authenticator || !fixture)
  // Credentials and recovery codes stay in the browser test process.
  test.setTimeout(210_000)
  const scoped = JSON.parse(await readFile(fixture!, 'utf8')) as HostedFixture
  const account = '/api/aegis/v1/account'
  const coverage = '/api/aegis/v1/coverage'
  const investigation = {
    snapshot_id: scoped.snapshot,
    question: 'Prioritize known exploited vulnerabilities',
  }
  const first = await login(page, scoped.users.foreign)
  const headers = (bearer: string) => ({ Authorization: bearer })
  const readCoverage = (bearer: string) => request.get(coverage, { headers: headers(bearer) })
  const direct = (bearer: string, runtime = scoped.runtime) => request.post(runtime, {
    headers: {
      Authorization: bearer,
      'Idempotency-Key': randomUUID(),
      'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id': randomUUID(),
    },
    data: investigation,
  })
  const group = (tab: Page) => tab.getByRole('region', { name: 'Verify with Authenticator' })
  const sendCode = async (tab: Page, code: string) => {
    await group(tab).getByLabel('Six-digit code').fill(code)
    const verification = tab.waitForResponse(response => response.url().endsWith(account + '/mfa/verify'))
    await group(tab).getByRole('button', { name: 'Verify code' }).click()
    return (await verification).status()
  }
  const setupKey = async (tab: Page) => {
    const value = group(tab).locator('p code')
    await expect(value).toBeVisible()
    return (await value.textContent())?.trim() ?? ''
  }
  const step = () => Math.floor(Date.now() / 30_000)
  const signOut = async (tab: Page) => {
    const hostedLogout = tab.waitForResponse(response => {
      const url = new URL(response.url())
      return url.hostname.endsWith('.amazoncognito.com') && url.pathname === '/logout'
    })
    await tab.getByRole('button', { name: 'Sign out', exact: true }).click()
    await hostedLogout
    await expect(tab.getByRole('link', { name: 'Sign in', exact: true })).toBeVisible()
  }
  const apiBefore = await readCoverage(first)
  expect(apiBefore.status()).toBe(403)
  expect((await apiBefore.json()).error.code).toBe('mfa_required')
  const runtimeBefore = await direct(first)
  expect([403, 424]).toContain(runtimeBefore.status())
  if (runtimeBefore.status() === 424) expect(await runtimeBefore.text()).toMatch(/403|mfa_required/)
  const legacy = new URL(scoped.runtime)
  legacy.searchParams.set('qualifier', '1')
  const legacyContext = await browser.newContext({ baseURL: target })
  let legacyStatus: number
  try {
    const approved = await login(await legacyContext.newPage(), scoped.users.member)
    const oldVersion = await direct(approved, legacy.href)
    legacyStatus = oldVersion.status()
    expect(oldVersion.ok()).toBe(false)
  } finally { await legacyContext.close() }
  await group(page).getByRole('button', { name: 'Set up Authenticator' }).click()
  const key = await setupKey(page)
  const firstStep = step()
  const firstCode = authenticatorCode(key, firstStep)
  expect(await sendCode(page, firstCode)).toBe(200)
  const codes = group(page).locator('li code')
  await expect(codes).toHaveCount(8)
  const recovery = (await codes.first().textContent())?.trim() ?? ''
  await page.getByRole('button', { name: 'I saved my recovery codes' }).click()
  await expect(page.getByRole('heading', { name: 'Threat command center.' })).toBeVisible()
  const avatarStyle = await page.locator('.avatar').getAttribute('style')
  await expect(page.locator('.avatar .avatar-mark')).toBeVisible()
  expect((await readCoverage(first)).status()).toBe(200)
  expect((await request.get('/api/aegis/v1/admin/users', { headers: headers(first) })).status()).toBe(404)
  expect((await request.post('/api/aegis/v1/admin/users/' + scoped.users.member.username, {
    headers: headers(first), data: { action: 'approve' },
  })).status()).toBe(404)
  expect((await request.post(account + '/photo', { headers: headers(first), data: {} })).status()).toBe(404)
  await signOut(page)
  expect((await readCoverage(first)).status()).toBe(401)

  const second = await login(page, scoped.users.foreign)
  expect((await readCoverage(second)).status()).toBe(403)
  expect(await sendCode(page, firstCode)).toBe(403)
  const accepted = new Set([step() - 1, step(), step() + 1].map(value => authenticatorCode(key, value)))
  const wrong = ['000000', '111111', '222222', '333333'].find(value => !accepted.has(value))!
  expect(await sendCode(page, wrong)).toBe(403)
  while (step() <= firstStep) await new Promise(resolve => setTimeout(resolve, 500))
  expect(await sendCode(page, authenticatorCode(key, step()))).toBe(200)
  await expect(page.locator('.avatar')).toHaveAttribute('style', avatarStyle!)
  const history = page.getByRole('region', { name: 'EPSS history' })
  await expect(history.getByLabel('Inspect EPSS date')).toBeVisible()
  await expect(history).toHaveAttribute('aria-busy', 'false')
  await history.getByLabel('EPSS start date').fill('2021-04-20')
  await history.getByLabel('EPSS end date').fill('2021-04-23')
  await history.getByRole('button', { name: 'Apply date range' }).click()
  await expect(history).toContainText('2 observed days · 2 dates absent from the source')
  const streamed = page.waitForResponse(response =>
    response.request().method() === 'POST' && response.url().endsWith('/api/aegis/v1/investigations'))
  await history.getByRole('button', { name: 'Analyze selected EPSS dates' }).click()
  const stream = await streamed
  expect(stream.status()).toBe(200)
  expect(stream.headers()['content-type']).toContain('text/event-stream')
  const frames = decode(await stream.text())
  expect(frames.map(frame => frame.seq)).toEqual(frames.map((_, index) => index + 1))
  expect(frames.filter(frame => frame.type === 'done')).toHaveLength(1)
  expect(frames.at(-1)?.payload.status).toBe('completed')

  const other = await browser.newContext({ baseURL: target })
  try {
    const recoveryPage = await other.newPage()
    const third = await login(recoveryPage, scoped.users.foreign)
    await group(recoveryPage).getByRole('button', { name: 'Use a recovery code' }).click()
    await group(recoveryPage).getByLabel('Recovery code').fill(recovery)
    await group(recoveryPage).getByRole('button', { name: 'Set up Authenticator' }).click()
    const replacement = await setupKey(recoveryPage)
    expect(replacement === key).toBe(false)
    expect((await readCoverage(second)).status()).toBe(403)
    expect((await readCoverage(third)).status()).toBe(403)
    expect(await sendCode(recoveryPage, authenticatorCode(replacement, step()))).toBe(200)
    await expect(group(recoveryPage).locator('li code')).toHaveCount(8)
    expect((await readCoverage(third)).status()).toBe(200)
    expect((await request.post(account + '/mfa/setup', {
      headers: headers(third), data: { recovery },
    })).status()).toBe(403)
    await recoveryPage.getByRole('button', { name: 'I saved my recovery codes' }).click()
    await signOut(recoveryPage)
    expect((await readCoverage(third)).status()).toBe(401)
  } finally { await other.close() }

  await writeFile(join(evidence, 'authenticator-pilot.json'), JSON.stringify({
    verified_email_fixture: true, approval_required: false, legacy_version_http: legacyStatus,
    api_before_totp: 403, agentcore_before_totp: runtimeBefore.status(),
    legacy_version_served_investigation: false, invalid_code: 403, reused_code: 403,
    recovered_only_after_new_totp: true, recovery_reuse: 403, logout_revoked: true,
    stable_avatar: true, admin_operations: 404, uploads: 404,
    streaming_events: frames.length, terminal: frames.at(-1)?.payload.status,
  }))
})

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
  if (v2) {
    for (const path of ['analytics/epss', 'catalog', 'network', 'cves/CVE-2024-3400']) {
      expect((await request.get('/api/aegis/v2/' + path)).status()).toBe(401)
    }
  }
  if (!fixture && !publicOnly) throw new Error('The hosted acceptance requires scoped identities.')
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
      expect((await request.post('/api/aegis/mcp', {
        headers: { Authorization: bearer, Accept: 'application/json, text/event-stream' },
        data: { jsonrpc: '2.0', method: 'tools/list', id: 1 },
      })).status()).toBe(404)
      expect((await request.get('/api/aegis/v1/coverage', {
        headers: { Authorization: bearer.replace(/\.([^.])([^.]*)$/, (_, first: string, rest: string) => '.' + (first === 'A' ? 'Q' : 'A') + rest) },
      })).status()).toBe(401)
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
  test.setTimeout(210_000)
  const scoped = JSON.parse(await readFile(fixture!, 'utf8')) as HostedFixture
  if (!scoped.hosted) throw new Error('A hosted validation fixture is required')
  const bearer = await login(page, scoped.users.member)
  const headers = { Authorization: bearer }
  await expect(page.getByRole('heading', { name: 'Threat command center.' })).toBeVisible()
  await expect(page.getByText('Exposure coverage unavailable')).toBeVisible()
  const world = page.locator('#exposure')
  const country = page.getByLabel('Map country')
  await expect(country).toHaveValue('')
  const globe = world.getByLabel('Interactive globe with Natural Earth boundaries').locator('canvas')
  await expect(globe).toBeVisible()
  await expect.poll(async () => {
    const png = await globe.screenshot({ path: join(evidence, 'production-world-map.png') })
    return page.evaluate(async (encoded) => {
      const bytes = Uint8Array.from(atob(encoded), char => char.charCodeAt(0))
      const bitmap = await createImageBitmap(new Blob([bytes], { type: 'image/png' }))
      const sample = new OffscreenCanvas(16, 16)
      const context = sample.getContext('2d')!
      context.drawImage(bitmap, 0, 0, sample.width, sample.height)
      bitmap.close()
      const pixels = context.getImageData(0, 0, sample.width, sample.height).data
      const blue = pixels.filter((_, index) => index % 4 === 2)
      return new Set(blue).size
    }, png.toString('base64'))
  }, { message: 'Wait for visible globe rendering' }).toBeGreaterThan(8)
  await country.selectOption('PE')
  if (v2) {
    await expect(world.getByLabel('Annual WDI network context')).toContainText('Peru')
    await expect(world.getByText('LTE population coverage unavailable')).toBeVisible()
  } else {
    await expect(world.getByText('Network context unavailable')).toBeVisible()
  }
  await expect(world.getByText('Exposure coverage unavailable')).toBeVisible()
  await country.selectOption('CA')
  await expect(world.getByText('Canadian Radio-television and Telecommunications Commission')).toBeVisible()
  await expect(world.getByText('Exposure coverage unavailable')).toBeVisible()
  await country.selectOption('')
  await expect(page.getByRole('region', { name: 'Ranked vulnerabilities' }).locator('tbody tr').first()).toBeVisible()
  if (v2) {
    const history = page.getByRole('region', { name: 'EPSS history' })
    await expect(history.locator('canvas')).toBeVisible({ timeout: 40000 })
    await history.getByRole('button', { name: 'Full history' }).click()
    await expect(history).toContainText('2,042 observed days · 9 dates absent from the source')
    await history.getByLabel('Inspect EPSS date').fill('2021-04-22')
    await expect(history).toContainText('2021-04-22 · No source observation')
    await history.getByLabel('EPSS start date').fill('2021-04-20')
    await history.getByLabel('EPSS end date').fill('2021-04-23')
    await history.getByRole('button', { name: 'Apply date range' }).click()
    await expect(history).toContainText('2 observed days · 2 dates absent from the source')
    await history.screenshot({ path: join(evidence, 'hosted-epss-history.png') })
    if (historicalAgent) {
      const historicalStream = page.waitForResponse(r =>
        r.request().method() === 'POST' && r.url().endsWith('/api/aegis/v1/investigations'))
      await history.getByRole('button', { name: 'Analyze selected EPSS dates' }).click()
      const streamed = await historicalStream
      expect(streamed.status()).toBe(200)
      expect(streamed.headers()['content-type']).toContain('text/event-stream')
      expect(streamed.request().postDataJSON().history).toMatchObject({
        date_from: '2021-04-20', date_to: '2021-04-23',
      })
      const historyReport = page.getByRole('article', { name: 'Investigation report' })
      await expect(historyReport).toContainText('Bedrock analysis', { timeout: 68000 })
      await expect(historyReport).toContainText('Country exposure is unavailable')
      const historyFrames = decode(await streamed.text())
      expect(historyFrames.map(frame => frame.seq)).toEqual(historyFrames.map((_, index) => index + 1))
      expect(historyFrames.filter(frame => frame.type === 'done')).toHaveLength(1)
      expect(historyFrames.at(-1)?.payload.status).toBe('completed')
      await writeFile(join(evidence, 'hosted-history-agent.json'), JSON.stringify(historyFrames))
      await historyReport.screenshot({ path: join(evidence, 'hosted-epss-analysis.png') })
    }
    const catalog = page.getByRole('region', { name: 'Vulnerability catalog' })
    await expect(catalog).toContainText('431,133 distinct CVEs')
    await catalog.getByLabel('CVE identifier').fill('CVE-2024-3400')
    await catalog.getByRole('button', { name: 'Search catalog' }).click()
    await catalog.getByRole('button', { name: 'CVE-2024-3400' }).click()
    await catalog.getByRole('button', { name: 'Open source profile' }).click()
    const profile = page.getByLabel('Official source profile')
    await expect(profile).toContainText('CVE exposure geography unavailable')
    const nvdCapture = profile.getByText('NIST NVD · 2024', { exact: true })
    await nvdCapture.click()
    await expect(nvdCapture.locator('..').getByText('Capture SHA-256')).toBeVisible()
    await page.screenshot({ path: join(evidence, 'hosted-cve-profile.png') })
    await page.getByRole('dialog', { name: 'CVE detail' }).getByRole('button', { name: 'Close', exact: true }).click()
  }
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
  expect((await request.post('/api/aegis/v1/admin/users/' + scoped.users.member.username, {
    headers: { ...headers, 'X-Role': 'administrator' },
    data: { action: 'suspend', expected_status: 'APPROVED', administrator: true },
  })).status()).toBe(403)
  const relationship = page.getByLabel('Inspect a relationship')
  await expect(relationship).toBeVisible({ timeout: 40_000 })
  await relationship.selectOption({ index: 1 })
  const card = page.getByRole('button', { name: 'Open CVE detail', exact: true })
  await expect(card).toBeVisible()
  await relationship.scrollIntoViewIfNeeded()
  await page.screenshot({ path: join(evidence, 'production-relationship-graph.png') })
  await page.screenshot({ path: join(evidence, 'production-command-center.png') })
  await card.click()
  await expect(page.getByRole('button', { name: 'How to mitigate' })).toBeVisible()
  const detailDialog = page.getByRole('dialog', { name: 'CVE detail' })
  await detailDialog.getByRole('button', { name: /^CISA/ }).click()
  const drawer = page.getByRole('dialog', { name: 'Evidence record' })
  await expect(drawer).toBeVisible()
  const evidenceId = drawer.getByText(/^[a-f0-9]{64}$/).first()
  await expect(evidenceId).toBeVisible()
  const evidencePath = '/api/aegis/v1/evidence/' + await evidenceId.innerText()
  const disclosure = await request.get(evidencePath, { headers })
  expect(disclosure.status()).toBe(200)
  const record = await disclosure.json()
  expect(record.snapshot_id).toBe(scoped.snapshot)
  expect(record.data.evidence_id).toBe(await evidenceId.innerText())
  expect((await request.get(evidencePath)).status()).toBe(401)
  await drawer.getByRole('button', { name: 'Close evidence' }).click()
  await card.click()
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
  const posts: string[] = []
  const observe = (r: typeof initial) => { if (r.method() === 'POST') posts.push(r.url()) }
  page.on('request', observe)
  try {
    await page.getByRole('button', { name: 'Request help' }).click()
    const draft = page.getByLabel('SOC / CSIRT handoff draft')
    await expect(draft).toHaveValue(new RegExp(scoped.snapshot))
    await draft.fill('Operator-reviewed acceptance draft')
    await expect(draft).toHaveValue('Operator-reviewed acceptance draft')
    expect(posts).toEqual([])
  } finally { page.off('request', observe) }
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
