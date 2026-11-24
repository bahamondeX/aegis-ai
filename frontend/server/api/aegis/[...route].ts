import { createHash } from 'node:crypto'

const reads = /^(health|v1\/(coverage|cves(?:\/CVE-\d{4}-\d{4,24})?|kpis|graph|map|evidence\/[a-f0-9]{64}))$/
const cancellation = /^v1\/investigations\/([a-f0-9-]{36})\/cancel$/

export default defineEventHandler(async (event) => {
  const route = getRouterParam(event, 'route') || ''
  const method = getMethod(event)
  const cancel = cancellation.exec(route)
  const investigating = method === 'POST' && (route === 'v1/investigations' || cancel)
  if (!(method === 'GET' && reads.test(route)) && !investigating) {
    throw createError({ statusCode: 404, statusMessage: 'Unknown AEGIS operation' })
  }
  const bearer = getHeader(event, 'authorization') || ''
  if (route !== 'health' && !/^Bearer [A-Za-z0-9._-]{1,8192}$/.test(bearer)) {
    throw createError({ statusCode: 401, statusMessage: 'A valid access token is required' })
  }
  const config = useRuntimeConfig(event)
  const base = new URL(config.aegisApiBase)
  const headers = new Headers({ Accept: 'application/json' })
  if (bearer) headers.set('Authorization', bearer)
  let target = new URL('/' + route, base)
  let body: string | undefined
  if (investigating) {
    headers.set('Content-Type', 'application/json')
    headers.set('Accept', cancel ? 'application/json' : 'text/event-stream')
    for (const key of ['Idempotency-Key', 'Last-Event-ID']) {
      const value = getHeader(event, key)
      if (value) headers.set(key, value)
    }
    const data: unknown = cancel ? undefined : await readBody(event)
    body = data === undefined ? undefined : JSON.stringify(data)
    if (config.aegisRuntimeUrl) {
      target = new URL(config.aegisRuntimeUrl)
      if (target.protocol !== 'https:' || !/^bedrock-agentcore\.[a-z0-9-]+\.amazonaws\.com$/.test(target.hostname)) {
        throw createError({ statusCode: 500, statusMessage: 'Invalid AgentCore destination' })
      }
      const session = createHash('sha256').update(bearer)
        .update(headers.get('Idempotency-Key') || 'cancel').digest('hex')
      headers.set('X-Amzn-Bedrock-AgentCore-Runtime-Session-Id', session)
      if (cancel) body = JSON.stringify({ action: 'cancel', investigation_id: cancel[1] })
    }
  } else {
    for (const [key, value] of Object.entries(getQuery(event))) {
      for (const item of Array.isArray(value) ? value : [value]) {
        if (typeof item === 'string') target.searchParams.append(key, item)
      }
    }
  }

  const abort = new AbortController()
  const disconnected = () => {
    if (!event.node.res.writableEnded) abort.abort()
  }
  event.node.res.once('close', disconnected)
  let upstream: Response
  try {
    upstream = await fetch(target, {
      method, headers, body, redirect: 'error',
      signal: AbortSignal.any([abort.signal, AbortSignal.timeout(65_000)]),
    })
  } catch {
    throw createError({ statusCode: 502, statusMessage: 'AEGIS service is unavailable' })
  }
  setResponseStatus(event, upstream.status)
  setResponseHeader(event, 'Cache-Control', 'no-store')
  setResponseHeader(event, 'Content-Type', upstream.headers.get('Content-Type') || 'application/json')
  if (!upstream.body) return ''
  return sendStream(event, upstream.body)
})
