import { Ajv } from 'ajv'
import addFormats from 'ajv-formats'
import type { CveDetail, MapProjection } from './geography.js'
import detailSchema from './cve-detail.schema.json' with { type: 'json' }
import mapSchema from './map.schema.json' with { type: 'json' }

const ajv = new Ajv({ strict: true })
addFormats.default(ajv)
const detail = ajv.compile<CveDetail>(detailSchema)
const geography = ajv.compile<MapProjection>(mapSchema)

export function verifiedDetail(value: unknown): CveDetail {
  if (!detail(value)) throw new Error('Invalid CVE detail')
  return value
}

export function verifiedMap<T>(value: T): T & MapProjection {
  if (!geography(value) || value.network.records.some(item => !item.publication.startsWith('https://'))) {
    throw new Error('Invalid geographic projection')
  }
  return value
}
