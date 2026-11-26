const reads = /^(v2\/(network|catalog|analytics\/epss|cves\/CVE-\d{4}-\d{4,24})|v1\/(account|coverage|cves(?:\/CVE-\d{4}-\d{4,24})?|kpis|graph|map|evidence\/[a-f0-9]{64}))$/
const actions = /^v1\/(investigations(?:\/[a-f0-9-]{36}\/cancel)?)$/

export default defineEventHandler(async (event) => {
  setResponseHeader(event, 'Cache-Control', 'no-store')
  const route = getRouterParam(event, 'route') || ''
  const method = getMethod(event)
  if (!(method === 'GET' && reads.test(route)) && !(method === 'POST' && actions.test(route))) {
    throw createError({ statusCode: 404, statusMessage: 'Unknown AEGIS operation' })
  }
  const config = useRuntimeConfig(event)
  const local = import.meta.dev && config.public.localTokenAuth
  if (method === 'POST') {
    if (local) {
      if (getHeader(event, 'origin') !== getRequestURL(event).origin) {
        throw createError({ statusCode: 403, statusMessage: 'Unapproved application origin' })
      }
    } else verifyWorkspaceOrigin(event)
  }
  const bearer = local ? getHeader(event, 'authorization') : await workspaceAssertion(event)
  let base: URL
  try {
    base = new URL(local ? config.localApiBase : config.aegisApiBase)
  } catch {
    throw createError({ statusCode: 503, statusMessage: 'Invalid AEGIS API destination' })
  }
  const allowed = local
    ? base.protocol === 'http:' && base.hostname === '127.0.0.1'
    : base.protocol === 'https:' && /^[a-z0-9]+\.execute-api\.us-east-1\.amazonaws\.com$/.test(base.host)
      && /^\/[a-z0-9_-]+\/?$/.test(base.pathname)
  if (!allowed || base.username || base.password || base.search || base.hash) {
    throw createError({ statusCode: 503, statusMessage: 'Invalid AEGIS API destination' })
  }
  const prefix = local ? '' : base.pathname.replace(/\/$/, '') + '/api/aegis'
  const target = new URL(prefix + '/' + route, base.origin)
  const streaming = route === 'v1/investigations'
  const headers = new Headers({
    Accept: streaming ? 'text/event-stream' : 'application/json',
  })
  if (bearer) headers.set('Authorization', bearer)
  let body: string | undefined
  if (method === 'POST') {
    for (const key of ['Idempotency-Key', 'Last-Event-ID']) {
      const value = getHeader(event, key)
      if (value) headers.set(key, value)
    }
    if (!route.endsWith('/cancel')) {
      headers.set('Content-Type', 'application/json')
      body = JSON.stringify(await readBody(event))
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
  try {
    const upstream = await fetch(target, {
      method, headers, body, redirect: 'error',
      signal: AbortSignal.any([abort.signal, AbortSignal.timeout(72_000)]),
    })
    setResponseStatus(event, upstream.status)
    setResponseHeader(event, 'Content-Type', upstream.headers.get('Content-Type') || 'application/json')
    if (streaming) setResponseHeader(event, 'X-Accel-Buffering', 'no')
    if (upstream.body) return await sendStream(event, upstream.body)
    return ''
  } catch {
    if (abort.signal.aborted) return
    if (event.node.res.headersSent) {
      event.node.res.destroy()
      return
    }
    throw createError({ statusCode: 502, statusMessage: 'AEGIS service is unavailable' })
  } finally {
    event.node.res.off('close', disconnected)
  }
})
