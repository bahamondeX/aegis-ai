import type { Feature, FeatureCollection, MultiPolygon, Polygon } from 'geojson'
import type { GeometryCollection, Topology } from 'topojson-specification'
import { feature, mesh } from 'topojson-client'
import countries from 'world-atlas/countries-110m.json'
import isoCountries from 'i18n-iso-countries'
import { areaColor, type Metric, type Observation, type Position } from '../../investigations/exposure'

import type { Exposure } from '../../investigations/events'

export type CountryFeature = Feature<Polygon | MultiPolygon, { name: string }>
type Countries = Topology<{ countries: GeometryCollection<{ name: string }> }>

const topology = countries as unknown as Countries
const outlines = feature(topology, topology.objects.countries) as FeatureCollection<
  Polygon | MultiPolygon, { name: string }
>

export function countryOutlines() {
  return outlines
}

export function countryBorders() {
  return mesh(topology, topology.objects.countries)
}

export function observedCountries(observations: Exposure[]) {
  return countryFeatures(observations.filter(row => (row.count ?? 0) > 0).map(row => row.country_iso2))
}

export function countryFeatures(countries: string[]) {
  const codes = new Set(countries.map(isoCountries.alpha2ToNumeric))
  return outlines.features.filter(row => row.id !== undefined && codes.has(String(row.id)))
}

function countryCode(row: CountryFeature) {
  return row.id === undefined ? '' : isoCountries.numericToAlpha2(row.id) ?? ''
}

function ringMoments(ring: number[][]) {
  const anchor = ring[0]?.[0] ?? 0
  const unwrap = (longitude: number) => anchor + ((longitude - anchor + 540) % 360) - 180
  let area = 0
  let x = 0
  let y = 0
  for (let i = 1; i < ring.length; i++) {
    const [x1, y1] = ring[i - 1] ?? []
    const [x2, y2] = ring[i] ?? []
    if (x1 === undefined || x2 === undefined || y1 === undefined || y2 === undefined) continue
    const a = unwrap(x1)
    const b = unwrap(x2)
    const cross = a * y2 - b * y1
    area += cross
    x += (a + b) * cross
    y += (y1 + y2) * cross
  }
  return { area, x, y }
}

function representative(row: CountryFeature): Position | undefined {
  const rings = row.geometry.type === 'Polygon'
    ? [row.geometry.coordinates[0]]
    : row.geometry.coordinates.map(polygon => polygon[0])
  let largest = 0
  let point: Position | undefined
  for (const ring of rings) {
    if (!ring) continue
    const { area, x, y } = ringMoments(ring)
    if (Math.abs(area) > largest) {
      largest = Math.abs(area)
      point = [((x / (3 * area) + 540) % 360) - 180, y / (3 * area)]
    }
  }
  return point
}

const countryCenters = new Map(outlines.features.flatMap(row => {
  const code = countryCode(row)
  const centroid = code ? representative(row) : undefined
  return centroid ? [[code, centroid] as const] : []
}))

export type HistoricalArea = { country: string; color: string; selected: boolean }
export type HistoricalShape = Feature<Polygon | MultiPolygon, HistoricalArea>
export type HistoricalMarker = { position: Position; id: string; count: number }

export function historicalMap(rows: Observation[], metric: Metric, country?: string) {
  const byCountry = new Map(rows.map(row => [row.context.area.country_iso2, row]))
  const shapes: HistoricalShape[] = outlines.features.map(row => {
    const code = countryCode(row)
    return {
      type: 'Feature',
      geometry: row.geometry,
      properties: { country: code, color: areaColor(byCountry.get(code), metric), selected: code === country },
    }
  })
  const markers: HistoricalMarker[] = rows.flatMap(row => {
    const position = countryCenters.get(row.context.area.country_iso2)
    return position ? [{ position, id: row.context.observation_id, count: row.distinct_cves }] : []
  })
  return { shapes, markers, center: country ? countryCenters.get(country) : undefined }
}
