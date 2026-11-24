"""Export the serialization schema used to validate the browser wire contract."""

import argparse
import json
from pathlib import Path

from backend.investigations.routes import ADAPTER
from pipelines.config import ROOT

SCHEMA = ROOT / "frontend" / "investigations" / "events.schema.json"


def schema_text() -> str:
    schema = ADAPTER.json_schema(mode="serialization")
    schema["title"] = "InvestigationEvent"
    # oneOf and per-variant const values encode the same discriminator in JSON Schema.
    schema.pop("discriminator")
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = schema_text()
    path = Path(SCHEMA)
    if args.check:
        if path.read_text() != rendered:
            raise SystemExit("investigation event schema differs from the backend")
    else:
        path.write_text(rendered)


if __name__ == "__main__":
    main()
