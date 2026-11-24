import type { Feature, FeatureCollection, MultiPolygon, Polygon } from 'geojson'
import type { GeometryCollection, Topology } from 'topojson-specification'
import { feature, mesh } from 'topojson-client'
import countries from 'world-atlas/countries-110m.json'
import { alpha2ToNumeric } from 'i18n-iso-countries'

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
  const codes = new Set(observations.map(row => alpha2ToNumeric(row.country_iso2)))
  return outlines.features.filter(row => row.id !== undefined && codes.has(String(row.id)))
}
