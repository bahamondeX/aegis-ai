import { writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { expect, test } from '@playwright/test'

const base = process.env.AEGIS_BROWSER_URL ?? ''
const evidence = process.env.AEGIS_BROWSER_EVIDENCE ?? '../data/evidence/cve-exposure-integration'
const authorizedOrigins = new Set(['https://aegis-candidate.vercel.app', 'https://aegis.oscarbahamonde.com'])
const enabled = process.env.AEGIS_BROWSER_RELEASE_AUTH === '1' && authorizedOrigins.has(base)
const readPath = '/api/aegis/v1/cves?limit=1'

if (enabled) test.use({ channel: 'chrome', headless: false })

test('registered origin keeps the OB Auth callback, CVE access, demo navigation and logout', async ({ page }) => {
  test.skip(!enabled, 'Requires a human sign-in at the registered release origin.')
  test.setTimeout(510_000)
  const options = { failOnStatusCode: false }
  const unauthenticated = await page.request.get(readPath, options)
  expect(unauthenticated.status()).toBe(401)

  await page.goto('/login')
  const loginResponse = page.waitForResponse(response => {
    const url = new URL(response.url())
    return url.origin === base && url.pathname === '/auth/login'
  })
  const callback = page.waitForResponse(response => {
    const url = new URL(response.url())
    return url.origin === base && url.pathname === '/auth/callback'
  }, { timeout: 450_000 })
  const account = page.waitForResponse(response => {
    const url = new URL(response.url())
    return url.origin === base && url.pathname === '/api/aegis/v1/account' && response.status() === 200
  }, { timeout: 455_000 })
  await page.getByRole('link', { name: 'Continue to OB Auth' }).click()
  const start = await loginResponse
  expect(start.status()).toBe(303)
  const location = new URL(start.headers().location ?? '')
  expect(location.origin).toBe('https://auth.oscarbahamonde.com')
  expect(location.searchParams.get('redirect_uri')).toBe(base + '/auth/callback')
  expect(location.searchParams.get('code_challenge_method')).toBe('S256')
  await page.waitForURL(url => url.origin === location.origin)
  await writeFile(join(evidence, 'auth-ready.json'), JSON.stringify({
    origin: base, provider: location.origin, preparedAt: new Date().toISOString(),
  }) + '\n', { mode: 0o600 })

  const returned = await callback
  expect(returned.status()).toBe(303)
  const destination = new URL(returned.headers().location ?? '', base)
  expect(destination.origin).toBe(base)
  expect(destination.pathname).toBe('/')
  expect((await account).status()).toBe(200)
  await expect(page.getByRole('heading', { name: 'Threat command center.' })).toBeVisible()
  const authorized = await page.request.get(readPath, options)
  expect(authorized.status()).toBe(200)
  const catalog = await page.request.get('/api/aegis/v2/catalog?year=2025&limit=1', options)
  expect(catalog.status()).toBe(200)

  const demoLink = page.getByRole('link', { name: 'Exposición a CVE · Demo histórica' })
  await expect(demoLink).toHaveAttribute('href', '/demo/exposure/')
  await demoLink.click()
  await expect(page.getByRole('heading', { name: 'Globo de exposición a CVE' })).toBeVisible()
  await page.getByRole('link', { name: 'Catálogo global de AEGIS', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Threat command center.' })).toBeVisible()

  const logout = page.waitForResponse(response =>
    response.request().method() === 'POST' && new URL(response.url()).pathname === '/auth/logout',
  )
  await page.locator('.sidebar-signout').click()
  const loggedOut = await logout
  expect(loggedOut.status()).toBe(204)
  const denied = await page.request.get(readPath, options)
  expect(denied.status()).toBe(401)

  await writeFile(join(evidence, 'auth-verified.json'), JSON.stringify({
    origin: base, checkedAt: new Date().toISOString(),
    loginStatus: start.status(), callbackStatus: returned.status(), callbackDestination: destination.pathname,
    accountStatus: 200, catalogStatus: catalog.status(),
    cveBefore: unauthenticated.status(), cveDuring: authorized.status(), logoutStatus: loggedOut.status(),
    cveAfter: denied.status(), demoNavigation: true,
  }, null, 2) + '\n', { mode: 0o600 })
})
