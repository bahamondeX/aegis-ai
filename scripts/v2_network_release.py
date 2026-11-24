"""Verify and commit the qualified WDI network context from existing AWS Bronze objects."""

import argparse
import json
from dataclasses import asdict
from datetime import date
from decimal import Decimal
from pathlib import Path

from botocore.exceptions import ClientError

from backend.v2_network import AnnualValue, Economy, NetworkContextReader, release_key, rows
from pipelines.bronze import PREFIX, ObjectRef, put_record, record
from pipelines.bronze_migrate import verified_lake
from pipelines.config import project_environment
from pipelines.epss_bronze import HEX, plan_id
from pipelines.io import DataError, write_json
from pipelines.wdi_context import INDICATOR
from scripts.v2_epss_campaign import scope

CAP = Decimal("0.15")
PREVIOUS_STAGES = Decimal("1.20")


def publish(identity: str) -> dict:
    environment = project_environment()
    settings = scope(environment)
    path = f"{settings.account}/{settings.region}/{settings.project}/bronze-migration/{identity}"
    bound = (
        sum(
            Decimal(environment.get(key, "0"))
            for key in ("AEGIS_V2_MIGRATION_USD", "AEGIS_V2_EPSS_PLAN_USD", "AEGIS_V2_HISTORY_USD")
        )
        + PREVIOUS_STAGES
        + CAP
    )
    if (
        not HEX.fullmatch(identity)
        or environment.get("AEGIS_V2_MIGRATION_APPROVAL") != path
        or not bound <= Decimal(environment.get("AEGIS_V2_ONE_TIME_BUDGET_USD", "0")) <= 15
    ):
        raise DataError("WDI staging requires the approved inventory and one-time scope")
    store = verified_lake(settings)
    migration = record(store, f"{PREFIX}/manifests/migrations/{identity}/committed.json")
    if not migration or migration["inventory_id"] != identity:
        raise DataError("committed Bronze network objects are missing")
    refs = {item["key"]: ObjectRef(**item) for item in migration["objects"]}
    selected = {
        Path(item["name"]).name: refs[item["key"]]
        for item in migration["inventory"]
        if item["name"].startswith("wdi/")
    }
    if len(selected) != 5 or any(store.inspect(ref.key) != ref for ref in selected.values()):
        raise DataError("the verified WDI inventory has changed")
    receipt = record(store, selected["receipt.json"].key)
    if not receipt or receipt["license"] != "CC BY 4.0":
        raise DataError("qualified WDI source terms or provenance are missing")
    manifest = {
        "schema_version": 1,
        "indicator": INDICATOR,
        "license": receipt["license"],
        "source_date": receipt["source_date"],
        "inventory": identity,
        "dimension": asdict(selected["country_dimension.parquet"]),
        "observations": asdict(selected["network_context.parquet"]),
        "source_receipt": asdict(selected["receipt.json"]),
        "counts": receipt["counts"],
    }
    digest = plan_id(manifest)
    # Reconcile the source data before publishing the immutable release pointer.
    countries = [
        Economy.model_validate(row) for row in rows(store, manifest["dimension"], max_rows=300)
    ]
    observations = [
        AnnualValue.model_validate(row)
        for row in rows(store, manifest["observations"], max_rows=20_000)
    ]
    reader = NetworkContextReader(
        digest,
        date.fromisoformat(receipt["source_date"]),
        countries,
        observations,
        receipt["counts"],
    )
    sample = reader.year(2024)
    if len(sample.data) != 217 or sample.economies_with_values != 151:
        raise DataError("WDI yearly denominator differs from the verified baseline")
    reused = not put_record(store, release_key(digest), manifest)
    pinned = NetworkContextReader.load(store, digest).year(2024)
    if pinned != sample:
        raise DataError("version-pinned network data differs from the staging validation")
    return {
        "release_id": digest,
        "reused": reused,
        "source_date": receipt["source_date"],
        **receipt["counts"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = publish(args.inventory)
    write_json(args.output, result)
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "release_id",
                    "countries_with_observations",
                    "normalized_observation_rows",
                )
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except ClientError as error:
        raise SystemExit(f"WDI staging AWS error: {error.response['Error']['Code']}") from None
    except (DataError, OSError, ValueError, KeyError) as error:
        raise SystemExit(f"WDI staging failed: {error}") from None
