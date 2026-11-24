import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { expect, test } from '@playwright/test'

const fixture = process.env.AEGIS_BROWSER_COGNITO_FIXTURE || ''
const evidence = process.env.AEGIS_BROWSER_EVIDENCE || '../data/evidence/g5'

test('Cognito authorization code with PKCE unlocks the workspace and streams from AgentCore', async ({ page }) => {
  test.skip(!fixture, 'Cognito verification requires the authorized project fixture.')
  const { users } = JSON.parse(await readFile(fixture, 'utf8'))
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto('/')
  await expect(page.getByLabel('Development access token')).toHaveCount(0)
  const authRequest = page.waitForRequest(request => {
    try { return new URL(request.url()).pathname === '/oauth2/authorize' } catch { return false }
  })
  await page.getByRole('button', { name: 'Continue with Cognito' }).click()
  const authorize = new URL((await authRequest).url())
  expect(authorize.searchParams.get('response_type')).toBe('code')
  expect(authorize.searchParams.get('code_challenge_method')).toBe('S256')
  expect(authorize.searchParams.get('code_challenge')).toBeTruthy()
  const form = page.locator('form').filter({ has: page.locator('input[name="username"]:visible') })
  await form.locator('input[name="username"]:visible').fill(users.member.username)
  await form.locator('input[name="password"]:visible').fill(users.member.password)
  await form.locator('input[type="submit"]:visible, button[type="submit"]:visible').first().click()
  await expect(page.getByText('Exposure coverage unavailable')).toBeVisible({ timeout: 30_000 })
  expect(new URL(page.url()).search).toBe('')
  const storage = await page.evaluate(() =>
    [...Object.values(localStorage), ...Object.values(sessionStorage)].join('\n'),
  )
  expect(storage).not.toMatch(/"access_token"|"refresh_token"/)

  const response = page.waitForResponse(res => res.url().endsWith('/api/aegis/v1/investigations'))
  await page.getByRole('button', { name: 'Prioritize known exploited vulnerabilities' }).click()
  expect((await response).headers()['content-type']).toContain('text/event-stream')
  await expect(page.getByRole('heading', { name: 'Verified findings' })).toBeVisible({ timeout: 70_000 })
  await expect(page.getByText('Bedrock analysis', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Apply', exact: true })).toBeVisible()
  await page.locator('#investigations').scrollIntoViewIfNeeded()
  await page.screenshot({ path: join(evidence, 'cognito-agentcore.png') })
  expect(errors).toEqual([])
})
