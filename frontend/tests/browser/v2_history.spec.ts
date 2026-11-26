import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { expect, test } from '@playwright/test'

const evidence = process.env.AEGIS_BROWSER_EVIDENCE || '../data/evidence/v2'
const tokenFile = process.env.AEGIS_BROWSER_TOKEN_FILE || ''

test('pinned EPSS history, absent days and source profiles in the combined workspace', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1040 })
  expect((await page.request.get('/api/aegis/v2/analytics/epss')).status()).toBe(401)
  expect((await page.request.get('/api/aegis/v2/cves/CVE-2024-3400')).status()).toBe(401)
  await page.goto('/')
  await page.getByLabel('Development access token').fill((await readFile(tokenFile, 'utf8')).trim())
  await page.getByRole('button', { name: 'Connect', exact: true }).click()
  const history = page.getByRole('region', { name: 'EPSS history' })
  await expect(history).toContainText('90 observed days')
  await expect(history.getByRole('img', { name: 'Global daily EPSS with gaps on dates lacking source observations' }).locator('canvas')).toBeVisible()
  const full = page.waitForResponse(response => response.url().endsWith('epss?all_dates=true'))
  await history.getByRole('button', { name: 'Full history' }).click()
  const data = await (await full).json()
  expect(data.snapshot_id).toBe('5416157301492221669')
  await expect(history).toContainText('2,042 observed days · 9 dates absent from the source')
  await history.getByText('Observed model changes').click()
  await expect(history).toContainText('2025-03-17 · v2025.03.14')
  await history.getByLabel('EPSS start date').fill('2021-04-20')
  await history.getByLabel('EPSS end date').fill('2021-04-23')
  await history.getByRole('button', { name: 'Apply date range' }).click()
  await expect(history).toContainText('2 observed days · 2 dates absent from the source')
  await history.getByLabel('Inspect EPSS date').fill('2021-04-22')
  await expect(history).toContainText('2021-04-22 · No source observation')
  await history.getByLabel('Compare EPSS date').fill('2021-04-20')
  await expect(history).toContainText('Comparison requires two observations from the same EPSS model')
  await history.getByLabel('Inspect EPSS date').fill('2021-04-21')
  await expect(history).toContainText('Mean difference')
  await history.getByRole('button', { name: 'Show network context for 2021' }).click()
  await expect(page.getByLabel('Network observation year')).toHaveValue('2021')
  await expect(page.getByLabel('Annual WDI network context')).toContainText('2021 · mobile cellular subscriptions')
  await expect(page.getByText('Exposure coverage unavailable')).toBeVisible()
  await history.screenshot({ path: join(evidence, 'epss-history.png') })
  if (process.env.NUXT_PUBLIC_HISTORY_ANALYSIS_V2 === 'true') {
    const stream = page.waitForResponse(response =>
      response.request().method() === 'POST' && response.url().endsWith('/api/aegis/v1/investigations'),
    )
    await history.getByRole('button', { name: 'Analyze selected EPSS dates' }).click()
    const result = await stream
    expect(result.status()).toBe(200)
    expect(result.request().postDataJSON().history).toMatchObject({ date_from: '2021-04-20', date_to: '2021-04-23' })
    const report = page.getByRole('article', { name: 'Investigation report' })
    await expect(report).toContainText('2 dates absent from this release')
    await expect(report).toContainText('Country exposure is unavailable')
    await report.getByRole('button', { name: /^Evidence / }).first().click()
    const evidenceRecord = page.getByRole('dialog', { name: 'Evidence record' })
    await expect(evidenceRecord).toBeVisible()
    await evidenceRecord.getByRole('button', { name: 'Close evidence' }).click()
    await page.screenshot({ path: join(evidence, 'epss-investigation.png') })
  }

  const catalog = page.getByRole('region', { name: 'Vulnerability catalog' })
  await catalog.getByLabel('CVE identifier').fill('CVE-2024-3400')
  await catalog.getByRole('button', { name: 'Search catalog' }).click()
  await catalog.getByRole('button', { name: 'CVE-2024-3400' }).click()
  await catalog.getByRole('button', { name: 'Open source profile' }).click()
  const profile = page.getByLabel('Official source profile')
  await expect(profile).toContainText('CVE exposure geography unavailable')
  await profile.getByText('NIST NVD · 2024').click()
  await expect(profile.getByRole('link', { name: 'Open official source' }).first()).toBeVisible()
  await expect(profile).toContainText('Capture SHA-256')
  await page.screenshot({ path: join(evidence, 'cve-source-profile.png') })
})
