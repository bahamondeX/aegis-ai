import { join } from 'node:path'
import { expect, test } from '@playwright/test'

const evidence = process.env.AEGIS_BROWSER_EVIDENCE ?? '../data/evidence/shadowserver-demo'
const source = 'https://www.shadowserver.org/news/shadowserver-2025-highlights-of-the-year-in-review/'

test('rotates and zooms the globe, opens a dated CVE and distinguishes missing observations', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  const requests: string[] = []
  page.on('request', request => requests.push(request.url()))
  await page.setViewportSize({ width: 1320, height: 1120 })
  const response = await page.goto('/demo/exposure/')
  expect(response?.status()).toBe(200)

  const map = page.getByRole('region', { name: 'Exposición a CVE' })
  const globe = map.getByLabel('Interactive globe with Natural Earth boundaries')
  await expect(globe.locator('canvas')).toBeVisible()
  const altitude = Number(await globe.getAttribute('data-altitude'))
  const longitude = Number(await globe.getAttribute('data-longitude'))
  expect(altitude).toBeGreaterThan(0)
  await globe.press('ArrowRight')
  await expect.poll(async () => Number(await globe.getAttribute('data-longitude'))).not.toBe(longitude)
  await page.getByRole('button', { name: 'Zoom in' }).click()
  await expect.poll(async () => Number(await globe.getAttribute('data-altitude'))).toBeLessThan(altitude)

  const area = map.getByLabel('Exposición del área')
  const country = map.getByLabel('Map country')
  await country.selectOption('CA')
  await expect(area.getByRole('heading', { name: 'Canadá' })).toBeVisible()
  await expect(area).toContainText('2025-07-20')
  await expect(area).toContainText('unpatched instances')
  await expect(area).toContainText('Cobertura parcial')
  await expect(area).toContainText('Recuento nacional no publicado')
  await expect(map.getByRole('link', { name: 'Fuente: The Shadowserver Foundation' })).toHaveAttribute('href', source)
  await map.getByLabel('Métrica').selectOption('severity')
  await expect(map.getByLabel('Leyenda del mapa')).toContainText('CVSS máximo')
  const cve = area.getByRole('button', { name: 'CVE-2025-54309' })
  await expect(cve).toBeVisible()
  await page.screenshot({ path: join(evidence, 'canada-exposicion.png') })
  await cve.click()
  const detail = page.getByRole('dialog', { name: 'Ficha CVE' })
  await expect(detail.getByRole('heading', { name: 'CVE-2025-54309' })).toBeVisible()
  await expect(detail).toContainText('9.8')
  await expect(detail).toContainText('CA · 2025-07-20')
  await expect(detail.getByRole('link', { name: 'Fuente: The Shadowserver Foundation' })).toHaveAttribute('href', source)
  await detail.screenshot({ path: join(evidence, 'ficha-cve.png') })
  await detail.getByRole('button', { name: 'Cerrar' }).click()

  await country.selectOption('BR')
  await expect(area.getByRole('heading', { name: 'Brasil' })).toBeVisible()
  await expect(area.getByText('Sin datos', { exact: true })).toBeVisible()
  await page.screenshot({ path: join(evidence, 'brasil-sin-datos.png') })

  await country.selectOption('US')
  await map.getByLabel('Fecha observada').fill('2025-01-16')
  await expect(area).toContainText('5,000 observadas')
  await map.getByRole('combobox', { name: 'CVE', exact: true }).selectOption('CVE-2025-54309')
  await expect(area.getByText('Sin datos', { exact: true })).toBeVisible()
  await map.getByRole('combobox', { name: 'CVE', exact: true }).selectOption('')
  await map.getByLabel('Fecha observada').fill('2025-02-01')
  await expect(area.getByText('Sin datos', { exact: true })).toBeVisible()
  expect(requests.filter(url => /\/api\/|dashboard\.shadowserver\.org/.test(url))).toEqual([])
  expect(errors).toEqual([])
})

test('maintains the historical list on mobile without WebGL', async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } })
  await context.addInitScript(() => {
    const original = HTMLCanvasElement.prototype.getContext
    Object.defineProperty(HTMLCanvasElement.prototype, 'getContext', {
      configurable: true,
      value(this: HTMLCanvasElement, type: string, ...args: unknown[]) {
        return /^webgl/i.test(type) ? null : Reflect.apply(original, this, [type, ...args])
      },
    })
  })
  try {
    const page = await context.newPage()
    expect((await page.goto('/demo/exposure/'))?.status()).toBe(200)
    const map = page.getByRole('region', { name: 'Exposición a CVE' })
    await expect(map.getByText('WebGL globe is unavailable on this device.')).toBeVisible()
    const country = map.getByLabel('Map country')
    await country.selectOption('CA')
    const area = map.getByLabel('Exposición del área')
    await expect(area.getByRole('button', { name: 'CVE-2025-54309' })).toBeVisible()
    await expect(map.getByRole('link', { name: 'Fuente: The Shadowserver Foundation' })).toHaveAttribute('href', source)
    await country.selectOption('BR')
    await expect(area.getByText('Sin datos', { exact: true })).toBeVisible()
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    await page.screenshot({ path: join(evidence, 'demo-mobile-sin-webgl.png'), fullPage: true })
  } finally {
    await context.close()
  }
})
