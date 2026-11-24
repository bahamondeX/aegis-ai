import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { expect, test, type Page } from '@playwright/test'

const evidence = process.env.AEGIS_BROWSER_EVIDENCE || '../data/evidence/g5'
const apiToken = process.env.AEGIS_BROWSER_TOKEN_FILE || ''

function observe(page: Page) {
  const failures: string[] = []
  page.on('pageerror', error => failures.push(error.message))
  page.on('console', message => {
    if (message.text().startsWith('Tactical map:')) console.log(message.text())
  })
  return failures
}

async function connect(page: Page) {
  const token = (await readFile(apiToken, 'utf8')).trim()
  await page.goto('/')
  await page.getByLabel('Development access token').fill(token)
  await page.getByRole('button', { name: 'Connect', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Threat command center.' })).toBeVisible()
  await expect(page.getByText('Exposure coverage unavailable')).toBeVisible()
  const upstream = await page.request.get('/api/aegis/v1/kpis?kev_only=true&limit=60', {
    headers: { Authorization: 'Bearer ' + token },
  })
  const { data } = await upstream.json()
  const total = Intl.NumberFormat('en-US').format(data.total_cves)
  await expect(page.getByLabel('Vulnerability metrics').getByText(total).first()).toBeVisible()
  return token
}

test('desktop command center streams an investigation and applies evidence-backed filters', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1040 })
  const failures = observe(page)
  await page.goto('/')
  const blocked = await page.request.get('/api/aegis/v1/kpis')
  expect(blocked.status()).toBe(401)
  await connect(page)
  await expect(page.locator('#exposure canvas').first()).toBeVisible()
  await expect(page.locator('#relationships canvas').first()).toBeVisible()
  await expect(page.locator('.analytics-chart canvas').first()).toBeVisible()
  await expect(page.locator('.map-observations')).toHaveCount(0)
  await page.screenshot({ path: join(evidence, 'desktop.png') })

  await page.getByRole('button', { name: 'Tactical', exact: true }).click()
  await expect(page.locator('.maplibregl-canvas').first()).toBeVisible()
  const map = page.getByLabel('Tactical map with Natural Earth boundaries')
  await expect(map).toHaveAttribute('data-rendered', 'true')
  expect((await map.boundingBox())?.height).toBeGreaterThan(240)
  await expect(page.getByRole('button', { name: 'Tactical', exact: true })).toHaveAttribute('aria-pressed', 'true')
  await page.screenshot({ path: join(evidence, 'tactical.png') })
  await page.getByRole('button', { name: 'Globe', exact: true }).click()

  const relation = page.getByLabel('Inspect a relationship')
  await relation.selectOption({ index: 1 })
  await page.locator('#relationships').getByRole('button', { name: 'Evidence' }).click()
  await expect(page.getByRole('dialog')).toBeVisible()
  await expect(page.getByText('Payload SHA-256')).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)

  const baseline = await page.locator('tbody tr').count()
  expect(baseline).toBeGreaterThan(3)
  const sent = page.waitForResponse(response =>
    response.url().endsWith('/api/aegis/v1/investigations') && response.request().method() === 'POST',
  )
  await page.getByRole('button', { name: 'Prioritize known exploited vulnerabilities' }).click()
  expect((await sent).headers()['content-type']).toContain('text/event-stream')
  await expect(page.getByRole('heading', { name: 'Verified findings' })).toBeVisible()
  await expect(page.getByLabel('Investigation progress').locator('li')).toHaveCount(4)
  await page.getByRole('button', { name: 'Apply', exact: true }).click()
  await expect(page.getByText('Filters applied to the workspace')).toBeVisible()
  await expect(page.locator('tbody tr')).toHaveCount(3)
  await page.locator('#investigations').scrollIntoViewIfNeeded()
  await page.screenshot({ path: join(evidence, 'investigation.png') })

  const reference = page.getByRole('article', { name: 'Investigation report' }).getByRole('button', { name: /^Evidence / }).first()
  await reference.click()
  await expect(page.getByRole('dialog')).toBeVisible()
  await page.screenshot({ path: join(evidence, 'evidence.png') })
  await page.getByRole('button', { name: 'Close evidence' }).click()
  await page.getByRole('button', { name: 'Filters', exact: true }).click()
  await page.getByLabel('Country code').fill('PE')
  await page.getByRole('button', { name: 'Apply filters' }).click()
  await expect(page.getByText('No ranked vulnerabilities match the active scope.')).toBeVisible()
  await expect(page.getByText('Exposure coverage unavailable')).toBeVisible()
  await expect(page.locator('.map-observations')).toHaveCount(0)
  expect(failures).toEqual([])
})

test('mobile layout retains navigation, filters and evidence coverage', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const failures = observe(page)
  await connect(page)
  await expect(page.locator('#exposure canvas').first()).toBeVisible()
  await page.getByRole('button', { name: 'Open navigation' }).click()
  await expect(page.getByRole('navigation', { name: 'Workspace navigation' })).toBeVisible()
  await page.getByRole('link', { name: 'Sources', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Source coverage' })).toBeVisible()
  await expect(page.getByText('CISA KEV', { exact: true })).toBeVisible()
  const horizontal = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)
  expect(horizontal).toBe(true)
  await page.screenshot({ path: join(evidence, 'mobile-sources.png') })
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }))
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0)
  await page.screenshot({ path: join(evidence, 'mobile.png') })
  expect(failures).toEqual([])
})

test('world and country context stay independent as a CVE moves from graph to an editable SOC handoff', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1040 })
  const failures = observe(page)
  await connect(page)
  const country = page.getByLabel('Map country')
  await expect(country).toHaveValue('')
  const map = page.locator('#exposure')
  await expect(map.getByText('Published network coverage', { exact: true }).last()).toBeVisible()
  await expect(map.getByText('Canadian Radio-television and Telecommunications Commission')).toBeVisible()
  await expect(map.getByLabel('Map legend')).toContainText('Measured zero')
  await expect(map.getByText('Exposure coverage unavailable')).toBeVisible()
  await page.screenshot({ path: join(evidence, 'world-layers.png') })

  await country.selectOption('PE')
  await expect(country).toHaveValue('PE')
  await expect(map.getByText('Network context unavailable')).toBeVisible()
  await expect(map.getByText('Exposure coverage unavailable')).toBeVisible()
  await expect(page.getByText('No ranked vulnerabilities match the active scope.')).toBeVisible()

  await country.selectOption('CA')
  await expect(country).toHaveValue('CA')
  await expect(map.getByText('Canadian Radio-television and Telecommunications Commission')).toBeVisible()
  await map.getByLabel('Network region').selectOption('Ontario')
  await expect(map.getByText('The map retains the country boundary.', { exact: false })).toBeVisible()
  await map.getByLabel('Network context', { exact: true }).uncheck()
  await expect(map.getByText('Canadian Radio-television and Telecommunications Commission')).toHaveCount(0)
  await expect(map.getByText('Exposure coverage unavailable')).toBeVisible()
  await map.getByLabel('Network context', { exact: true }).check()
  await map.getByLabel('CVE geographic evidence').uncheck()
  await expect(map.getByText('Exposure coverage unavailable')).toHaveCount(0)
  await expect(map.getByText('Canadian Radio-television and Telecommunications Commission')).toBeVisible()
  await map.getByLabel('CVE geographic evidence').check()
  await country.selectOption('')
  await expect(page.locator('tbody tr').first()).toBeVisible()

  const relation = page.getByLabel('Inspect a relationship')
  await relation.selectOption({ index: 1 })
  const selected = await relation.locator('option:checked').innerText()
  const cve = selected.split(' · ')[0]!
  const route = '/api/aegis/v1/cves/' + cve
  expect((await page.request.get(route)).status()).toBe(401)
  await page.getByRole('button', { name: 'Open CVE detail' }).click()
  const dialog = page.getByRole('dialog', { name: 'CVE detail' })
  await expect(dialog.getByRole('heading', { name: cve, exact: true })).toBeVisible()
  await expect(dialog.getByText('EPSS probability')).toBeVisible()
  await expect(dialog.getByText('No qualified CVE exposure source', { exact: false })).toBeVisible()
  await expect(dialog.getByRole('button', { name: /^CISA/ })).toBeVisible()
  await page.screenshot({ path: join(evidence, 'cve-detail.png') })
  await dialog.getByRole('button', { name: 'Close', exact: true }).click()
  await page.getByRole('button', { name: 'Filter workspace to CVE' }).click()
  await country.selectOption('CA')
  await expect(map.getByText('Canadian Radio-television and Telecommunications Commission')).toBeVisible()
  await expect(page.getByText('No ranked vulnerabilities match the active scope.')).toBeVisible()
  await page.getByRole('button', { name: 'Open CVE detail for ' + cve }).click()
  await expect(dialog.getByText('Geographic evidence · CA')).toBeVisible()

  const stream = page.waitForResponse(response =>
    response.url().endsWith('/api/aegis/v1/investigations') && response.request().method() === 'POST',
  )
  await dialog.getByRole('button', { name: 'How to mitigate' }).click()
  const response = await stream
  expect(response.headers()['content-type']).toContain('text/event-stream')
  const payload = response.request().postDataJSON()
  expect(payload.filters.cve_ids).toEqual([cve])
  expect(payload.filters.country_iso2).toBe('CA')
  expect(payload.mitigation.evidence_ids.length).toBeGreaterThan(0)
  const report = page.getByRole('article', { name: 'Investigation report' })
  await expect(report).toContainText('CISA KEV required action')
  await expect(report).toContainText('Deterministic analysis')
  await expect(page.getByLabel('Investigation progress').locator('li')).toHaveCount(4)
  await expect(map.getByText('Canadian Radio-television and Telecommunications Commission')).toBeVisible()
  const unauthorized = (await page.request.get(route + '?snapshot_id=' + payload.snapshot_id, {
    headers: { Authorization: 'Bearer wrong-token' },
  }))
  expect(unauthorized.status()).toBe(401)

  const outbound: string[] = []
  page.on('request', request => { if (request.method() === 'POST') outbound.push(request.url()) })
  await report.getByRole('button', { name: 'Request help' }).click()
  const draft = report.getByLabel('SOC / CSIRT handoff draft')
  await expect(draft).toHaveValue(new RegExp(payload.snapshot_id))
  await expect(draft).toHaveValue(new RegExp(cve))
  await draft.scrollIntoViewIfNeeded()
  await page.screenshot({ path: join(evidence, 'soc-handoff.png') })
  await draft.fill('Operator-reviewed handoff')
  await expect(draft).toHaveValue('Operator-reviewed handoff')
  expect(outbound).toEqual([])
  expect(failures).toEqual([])
})
