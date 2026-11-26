import { createHmac } from 'node:crypto'
import { createServerAuth, type ServerAuthOptions } from '@oscarbahamonde/ob-auth/server'
import type { H3Event } from 'h3'

function settings(event: H3Event) {
  const config = useRuntimeConfig(event).obAuth as ServerAuthOptions
  try {
    if (new URL(config.appOrigin).host !== getHeader(event, 'host')) {
      throw createError({ statusCode: 403, statusMessage: 'Unapproved application origin' })
    }
  } catch (error) {
    if (error instanceof TypeError) {
      throw createError({ statusCode: 503, statusMessage: 'Application authentication is unavailable' })
    }
    throw error
  }
  return config
}

export function obAuth(event: H3Event) {
  return createServerAuth(settings(event))
}

export function verifyWorkspaceOrigin(event: H3Event) {
  const { appOrigin } = settings(event)
  if (getHeader(event, 'origin') !== appOrigin) {
    throw createError({ statusCode: 403, statusMessage: 'Unapproved application origin' })
  }
}

export async function workspaceAssertion(event: H3Event) {
  const config = settings(event)
  const signingKey = useRuntimeConfig(event).aegisBridgeSigningKey
  if (!/^[A-Za-z0-9_-]{43}$/.test(signingKey)) {
    throw createError({ statusCode: 503, statusMessage: 'AEGIS authentication is unavailable' })
  }
  const tenant = getHeader(event, 'x-aegis-tenant')
  if (tenant && !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(tenant)) {
    throw createError({ statusCode: 422, statusMessage: 'Invalid workspace identifier' })
  }

  // The SDK keeps its grant in the sealed HttpOnly cookie. Use its fetch
  // extension at the documented introspection exchange rather than reading that cookie.
  let grant = ''
  const auth = createServerAuth(config, async (input, init) => {
    if (String(input) === config.domain + '/api/auth/introspect' && typeof init?.body === 'string') {
      const body = JSON.parse(init.body) as { grant?: string }
      grant = body.grant ?? ''
    }
    return fetch(input, init)
  })
  const session = await auth.requireAuth(event)
  if (!/^[A-Za-z0-9_-]{43}$/.test(grant)) {
    throw createError({ statusCode: 503, statusMessage: 'AEGIS authentication is unavailable' })
  }
  const { emailVerified, provider, mfa } = session.user
  if (!emailVerified || !(provider === 'google' || (provider === 'password' && mfa))) {
    throw createError({ statusCode: 403, statusMessage: 'Verified email required. Password sign-in requires an authenticator.' })
  }
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url')
  const now = Math.floor(Date.now() / 1000)
  const payload = encode({
    iss: 'aegis-nitro',
    aud: 'aegis-aws',
    sub: session.user.sub,
    grant,
    iat: now,
    exp: Math.min(session.expiresAt, now + 120),
    ...(tenant ? { tenant } : {}),
  })
  const message = encode({ alg: 'HS256', typ: 'JWT', kid: config.clientId }) + '.' + payload
  return 'Bearer ' + message + '.' + createHmac('sha256', signingKey).update(message).digest('base64url')
}
