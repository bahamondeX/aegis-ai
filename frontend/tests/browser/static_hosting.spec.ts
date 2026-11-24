import { join } from 'node:path'
import { expect, test } from '@playwright/test'

const staticRun = process.env.AEGIS_BROWSER_STATIC === '1'
const evidence = process.env.AEGIS_BROWSER_EVIDENCE || '../data/evidence/continuation'

test('hosted static artifact requires Cognito and starts PKCE locally', async ({ page }) => {
  test.skip(!staticRun, 'Requires the separate static artifact server.')
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.route(/^https:\/\/[^/]+\/oauth2\/authorize\?/, route => route.abort())
  // The static browser test performs no external sign-in or service calls.
  await page.goto('/')
  await expect(page.getByLabel('Development access token')).toHaveCount(0)
  const login = page.getByRole('button', { name: 'Continue with Cognito' })
  await expect(login).toBeVisible()
  await page.screenshot({ path: join(evidence, 'static-login.png') })
  const pending = page.waitForRequest(request => new URL(request.url()).pathname === '/oauth2/authorize')
  await login.click()
  const request = new URL((await pending).url())
  expect(request.searchParams.get('response_type')).toBe('code')
  expect(request.searchParams.get('code_challenge_method')).toBe('S256')
  expect(request.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/)
  expect(request.searchParams.get('redirect_uri')).toBe(process.env.AEGIS_BROWSER_URL + '/auth/callback')
  await page.goto('/auth/callback/')
  await expect(page.getByText('Connection failed.', { exact: false })).toBeVisible()
  const local = await page.evaluate(() => [...Object.values(localStorage), ...Object.values(sessionStorage)].join('\n'))
  expect(local).not.toMatch(/"access_token"|"refresh_token"/)
  expect(errors).toEqual([])
})
