"""Stage independent ITU mobile subscription context via the World Bank WDI API."""

import argparse
import json
import math
import re
import tempfile
from collections import Counter
from datetime import date
from pathlib import Path

import httpx
import pyarrow as pa
import pyarrow.parquet as pq

from pipelines.bulk_archive import transfer
from pipelines.config import project_environment
from pipelines.io import DataError, digest, file_digest, write_json

COUNTRIES_URI = "https://api.worldbank.org/v2/country?format=json&per_page=400"
INDICATOR = "IT.CEL.SETS.P2"
INDICATOR_URI = (
    f"https://api.worldbank.org/v2/country/all/indicator/{INDICATOR}"
    "?format=json&per_page=20000&source=2"
)
INDICATOR_PAGE = f"https://data.worldbank.org/indicator/{INDICATOR}"


def single_page(path: Path) -> tuple[dict, list[dict]]:
    metadata, rows = json.loads(path.read_bytes())
    if metadata["pages"] != 1 or metadata["page"] != 1 or metadata["total"] != len(rows):
        raise DataError("WDI response count or page manifest is incomplete")
    return metadata, rows


def project(economies: list[dict], measures: list[dict]) -> tuple[list[dict], list[dict], dict]:
    all_economies = set()
    countries = {}
    for row in economies:
        code = row["id"]
        if code in all_economies:
            raise DataError("WDI country manifest has duplicate economy codes")
        all_economies.add(code)
        region = row["region"]
        if region["id"] == "NA" or region["value"].strip() == "Aggregates":
            continue
        if not re.fullmatch(r"[A-Z]{2}", row["iso2Code"]):
            raise DataError("WDI country manifest has an invalid alpha-2 code")
        countries[code] = {
            "economy_code": code,
            "alpha2": row["iso2Code"],
            "name": row["name"],
            "region_code": region["id"],
            "region_name": region["value"].strip(),
        }
    if len({entry["alpha2"] for entry in countries.values()}) != len(countries):
        raise DataError("WDI country dimension has duplicate alpha-2 codes")
    observations = []
    latest: dict[str, int] = {}
    years: Counter[int] = Counter()
    seen: set[tuple[str, int]] = set()
    missing = aggregate = unmatched = measured_zero = 0
    for row in measures:
        if row["indicator"]["id"] != INDICATOR:
            raise DataError("WDI returned an unexpected indicator")
        code = row["countryiso3code"]
        if code not in countries:
            if code in all_economies:
                aggregate += 1
            else:
                unmatched += 1
            continue
        year = int(row["date"])
        if (code, year) in seen:
            raise DataError("WDI reported duplicate economy and year")
        seen.add((code, year))
        value = row["value"]
        if value is None:
            missing += 1
        elif type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise DataError("WDI reported an invalid subscription value")
        else:
            value = float(value)
            measured_zero += value == 0
            latest[code] = max(latest.get(code, year), year)
            years[year] += 1
        observations.append(
            {
                "economy_code": code,
                "year": year,
                "indicator": INDICATOR,
                "subscriptions_per_100_people": value,
            }
        )
    return (
        list(countries.values()),
        observations,
        {
            "source_country_rows": len(economies),
            "source_observation_rows": len(measures),
            "country_dimension_rows": len(countries),
            "normalized_observation_rows": len(observations),
            "country_rows_with_value": sum(years.values()),
            "country_rows_missing": missing,
            "source_measured_zero_rows": measured_zero,
            "aggregate_rows_excluded": aggregate,
            "unmatched_rows_excluded": unmatched,
            "countries_with_observations": len(latest),
            "countries_by_most_recent_year": dict(Counter(latest.values())),
            "country_coverage_by_year": dict(sorted(years.items())),
        },
    )


def capture(root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root) as working:
        staging = Path(working)
        uri = {"countries": COUNTRIES_URI, "indicator": INDICATOR_URI}
        with httpx.Client(follow_redirects=True, timeout=25) as client:
            captured = {
                key: {"uri": url, **transfer(client, url, staging / f"{key}.json", 16 * 1024**2)}
                for key, url in uri.items()
            }
        _, economies = single_page(staging / "countries.json")
        index, measures = single_page(staging / "indicator.json")
        countries, facts, counts = project(economies, measures)
        if not countries or not facts:
            raise DataError("WDI response has no country-level observations")
        revision = digest("".join(str(row["sha256"]) for row in captured.values()).encode())
        source_date = date.fromisoformat(index["lastupdated"]).isoformat()
        folder = root / source_date / revision
        folder.mkdir(parents=True, exist_ok=True)
        manifest = folder / "receipt.json"
        if manifest.is_file():
            receipt = json.loads(manifest.read_text())
            if any(
                file_digest(folder / f"{key}.json") != item["sha256"]
                for key, item in captured.items()
            ) or any(
                file_digest(folder / f"{key}.parquet") != item["sha256"]
                for key, item in receipt["files"].items()
            ):
                raise DataError("cached WDI release differs from its recorded checksums")
            return {"artifact": str(folder), "cached": True, **receipt}
        for key in captured:
            (staging / f"{key}.json").replace(folder / f"{key}.json")
        files = {}
        for name, rows in (("country_dimension", countries), ("network_context", facts)):
            output = folder / f"{name}.parquet"
            pq.write_table(pa.Table.from_pylist(rows), staging / output.name, compression="zstd")
            (staging / output.name).replace(output)
            files[name] = {"sha256": file_digest(output), "bytes": output.stat().st_size}
        receipt = {
            "schema_version": 1,
            "source_date": source_date,
            "source": "World Bank WDI (source 2), International Telecommunication Union",
            "citation": INDICATOR_PAGE,
            "license": "CC BY 4.0",
            "geographic_basis": "reported_economy_subscription_rate",
            "captures": captured,
            "files": files,
            "counts": counts,
        }
        write_json(manifest, receipt)
        return {"artifact": str(folder), "cached": False, **receipt}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()
    env = project_environment()
    root = args.root or Path(env.get("AEGIS_DATA_DIR") or "data") / "v2/wdi"
    print(json.dumps(capture(root.resolve()), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (DataError, KeyError, TypeError, ValueError, OSError) as error:
        raise SystemExit(f"WDI context capture failed: {error}") from None
