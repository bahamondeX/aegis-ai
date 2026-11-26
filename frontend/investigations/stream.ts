import { Ajv } from 'ajv'
import addFormatsModule from 'ajv-formats'

import type { MitigationContext } from './geography.js'
import type { Filters, InvestigationEvent } from './events.js'
import eventSchema from './events.schema.json' with { type: 'json' }

const ajv = new Ajv({ strict: true })
addFormatsModule.default(ajv)
const validate = ajv.compile<InvestigationEvent>(eventSchema)
const maximumFrame = 256 * 1024
const day = 86_400_000

export interface HistorySelection {
  release_id: string
  date_from: string
  date_to: string
}

interface InvestigationRequest {
  question: string
  scope?: 'global' | 'regional'
  filters?: Filters
  snapshot_id?: string
  mitigation?: MitigationContext
  history?: HistorySelection
}

interface StreamOptions {
  endpoint: URL
  token: string
  key: string
  request: InvestigationRequest
  signal?: AbortSignal
  after?: number
}

function decodeFrame(frame: string): InvestigationEvent | undefined {
  const lines = frame.split(/\r?\n/)
  const id = lines.find(line => line.startsWith('id: '))?.slice(4)
  const type = lines.find(line => line.startsWith('event: '))?.slice(7)
  const data = lines.filter(line => line.startsWith('data: ')).map(line => line.slice(6))
  if (data.length === 0 && lines.every(line => line.startsWith(':'))) return undefined
  const value: unknown = JSON.parse(data.join('\n'))
  if (!validate(value) || id !== String(value.seq) || type !== value.type) {
    throw new Error('Invalid investigation event')
  }
  if (value.type === 'ui.filters.proposed') {
    const { date_from: from, date_to: to } = value.payload.filters
    if (from && to) {
      const days = (Date.parse(to) - Date.parse(from)) / day
      if (days < 0 || days > 3660) throw new Error('Invalid filter date range')
    }
  }
  return value
}

export async function* decodeInvestigation(
  stream: ReadableStream<Uint8Array>,
  after = 0,
): AsyncGenerator<InvestigationEvent> {
  let sequence = after
  let identifier: string | undefined
  let buffer = ''
  let terminal = false
  if (!Number.isInteger(after) || after < 0) throw new Error('Invalid event cursor')
  const reader = stream.getReader()
  const decoder = new TextDecoder('utf-8', { fatal: true })
  try {
    while (true) {
      const part = await reader.read()
      if (part.done) break
      buffer += decoder.decode(part.value, { stream: true })
      let separator = /\r?\n\r?\n/.exec(buffer)
      while (separator) {
        if (separator.index > maximumFrame) throw new Error('Investigation frame too large')
        const event = decodeFrame(buffer.slice(0, separator.index))
        buffer = buffer.slice(separator.index + separator[0].length)
        if (event) {
          if (
            terminal ||
            event.seq !== sequence + 1 ||
            (sequence === 0 && event.type !== 'investigation.started') ||
            (sequence > 0 && event.type === 'investigation.started') ||
            (identifier !== undefined && event.investigation_id !== identifier)
          ) throw new Error('Out-of-order investigation stream')
          sequence = event.seq
          identifier = event.investigation_id
          terminal = event.type === 'done'
          yield event
        }
        separator = /\r?\n\r?\n/.exec(buffer)
      }
      if (buffer.length > maximumFrame) throw new Error('Investigation frame too large')
    }
    buffer += decoder.decode()
    if (buffer.length > 0 || (!terminal && (after === 0 || sequence !== after))) {
      throw new Error('Investigation stream ended before done')
    }
  } finally {
    try {
      await reader.cancel()
    } finally {
      reader.releaseLock()
    }
  }
}

export async function* readInvestigation(options: StreamOptions): AsyncGenerator<InvestigationEvent> {
  const headers = {
    ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}),
    Accept: 'text/event-stream',
    'Content-Type': 'application/json',
    'Idempotency-Key': options.key,
    ...(options.after === undefined ? {} : { 'Last-Event-ID': String(options.after) }),
  }
  const response = await fetch(options.endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify(options.request),
    cache: 'no-store',
    redirect: 'error',
    signal: options.signal,
  })
  if (!response.ok || !response.body ||
      !response.headers.get('content-type')?.startsWith('text/event-stream')) {
    await response.body?.cancel()
    throw new Error(`Investigation request failed (${response.status})`)
  }
  yield* decodeInvestigation(response.body, options.after)
}
