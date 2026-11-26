import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { expect, test } from '@playwright/test'

const evidence = process.env.AEGIS_BROWSER_EVIDENCE || '../data/evidence/v2-catalog'
const tokenFile = process.env.AEGIS_BROWSER_TOKEN_FILE || ''

test('official catalog pages and exact CVE source overview use the staged AWS release', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1040 })
  expect((await page.request.get('/api/aegis/v2/catalog')).status()).toBe(401)
  await page.goto('/')
  await page.getByLabel('Development access token').fill((await readFile(tokenFile, 'utf8')).trim())
  await page.getByRole('button', { name: 'Connect', exact: true }).click()
  await page.getByRole('link', { name: 'Vulnerability catalog' }).click()
  const catalog = page.getByRole('region', { name: 'Vulnerability catalog' })
  await expect(catalog).toContainText('431,133 distinct CVEs')
  await expect(catalog.locator('tbody tr')).toHaveCount(20)
  const first = await catalog.locator('tbody tr').first().textContent()
  await catalog.getByRole('button', { name: 'Next catalog page' }).click()
  await expect(catalog.locator('tbody tr').first()).not.toHaveText(first || '')
  await expect(catalog.locator('tbody tr')).toHaveCount(20)
  await catalog.getByRole('button', { name: 'Previous catalog page' }).click()
  await expect(catalog.locator('tbody tr').first()).toHaveText(first || '')
  await catalog.getByLabel('CVE identifier').fill('CVE-2024-3400')
  const lookup = page.waitForResponse(response => response.url().includes('cve_id=CVE-2024-3400'), { timeout: 55000 })
  await catalog.getByRole('button', { name: 'Search catalog' }).click()
  expect((await lookup).status()).toBe(200)
  await expect(catalog.locator('tbody tr')).toHaveCount(1)
  await catalog.getByRole('button', { name: 'CVE-2024-3400' }).click()
  const overview = catalog.getByLabel('CVE source overview')
  await expect(overview.getByRole('heading', { name: 'CVE-2024-3400' })).toBeVisible()
  await expect(overview.getByRole('link', { name: 'NIST NVD' })).toBeVisible()
  await expect(overview.getByRole('link', { name: 'CISA KEV' })).toBeVisible()
  await page.screenshot({ path: join(evidence, 'catalog-source-overview.png') })
})
