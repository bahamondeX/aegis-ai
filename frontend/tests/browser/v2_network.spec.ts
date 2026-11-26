import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { expect, test } from '@playwright/test'

const evidence = process.env.AEGIS_BROWSER_EVIDENCE || '../data/evidence/v2-network'
const tokenFile = process.env.AEGIS_BROWSER_TOKEN_FILE || ''

test('annual WDI context loads actual staged data independently of CVE exposure', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1040 })
  const denied = await page.request.get('/api/aegis/v2/network?year=2024')
  expect(denied.status()).toBe(401)
  await page.goto('/')
  const token = (await readFile(tokenFile, 'utf8')).trim()
  await page.getByLabel('Development access token').fill(token)
  const loaded = page.waitForResponse(response => response.url().endsWith('/v2/network?year=2024'), { timeout: 20000 })
  await page.getByRole('button', { name: 'Connect', exact: true }).click()
  const result = await loaded
  expect(result.status()).toBe(200)
  const initial = await result.json()
  expect(initial.economies_with_values).toBe(151)
  expect(initial.economies_in_scope).toBe(217)
  const annual = page.getByLabel('Annual WDI network context')
  await expect(annual).toContainText('151 of 217 economies reported values')
  await expect(page.getByText('Exposure coverage unavailable')).toBeVisible()
  const globe = page.getByLabel('Interactive globe with Natural Earth boundaries')
  await expect(globe.locator('canvas').first()).toBeVisible()
  const before = Number(await globe.getAttribute('data-altitude'))
  await page.getByRole('group', { name: 'Globe camera' }).getByRole('button', { name: 'Zoom in' }).click()
  await expect.poll(async () => Number(await globe.getAttribute('data-altitude'))).toBeLessThan(before)
  const altitude = await globe.getAttribute('data-altitude')
  await page.getByLabel('Map country', { exact: true }).selectOption('PE')
  await expect(annual).toContainText('Peru')
  await expect(globe).toHaveAttribute('data-altitude', altitude!)
  const earlier = page.waitForResponse(response => response.url().endsWith('/v2/network?year=2000'))
  await page.getByLabel('Network observation year').selectOption('2000')
  const response = await earlier
  expect(response.status()).toBe(200)
  const historical = await response.json()
  expect(historical.release_id).toBe(initial.release_id)
  expect(historical.year).toBe(2000)
  const current = initial.data.find((row: { economy: { alpha2: string } }) => row.economy.alpha2 === 'PE')
  const older = historical.data.find((row: { economy: { alpha2: string } }) => row.economy.alpha2 === 'PE')
  expect(older.value).not.toEqual(current.value)
  await expect(annual).toContainText('2000 · mobile cellular subscriptions per 100 people')
  await expect(page.getByText('Exposure coverage unavailable')).toBeVisible()
  await page.getByRole('checkbox', { name: 'Mobile subscriptions' }).uncheck()
  await expect(annual).toHaveCount(0)
  await expect(page.getByText('Exposure coverage unavailable')).toBeVisible()
  await page.getByRole('checkbox', { name: 'Mobile subscriptions' }).check()
  await expect(annual).toContainText('2000')
  await page.screenshot({ path: join(evidence, 'annual-network.png') })
})
