"""Read allowlisted project options from the root dotenv file as literal data."""

import os
import stat
from pathlib import Path
from uuid import UUID

from dotenv import dotenv_values

from pipelines.io import DataError

ROOT = Path(__file__).resolve().parents[1]
PROJECT_OPTIONS = (
    "AEGIS_AWS_ACCOUNT",
    "AEGIS_AWS_REGION",
    "AEGIS_AWS_PROFILE",
    "AEGIS_PROJECT_PREFIX",
    "AEGIS_DEPLOY_APPROVAL",
    "AEGIS_BUDGET_USD",
    "AEGIS_SCHEDULE_ENABLED",
    "AEGIS_CDK_EXECUTION_POLICY_ARN",
    "AEGIS_DESTROY_APPROVAL",
    "AEGIS_DATA_DIR",
    "AEGIS_SNAPSHOT",
    "BEDROCK_MODEL_ID",
    "AEGIS_BEDROCK_APPROVAL",
    "AEGIS_BEDROCK_BUDGET_USD",
    "AEGIS_BEDROCK_TOTAL_BUDGET_USD",
    "AEGIS_BEDROCK_RUNTIME_BUDGET_USD",
    "AEGIS_BEDROCK_INPUT_USD_PER_MILLION",
    "AEGIS_BEDROCK_OUTPUT_USD_PER_MILLION",
    "AEGIS_AGENTCORE_APPROVAL",
    "AEGIS_AGENTCORE_BUDGET_USD",
    "AEGIS_HOSTING_APPROVAL",
    "AEGIS_HOSTING_BUDGET_USD",
    "AEGIS_V2_MIGRATION_APPROVAL",
    "AEGIS_V2_MIGRATION_USD",
    "AEGIS_V2_MIGRATION_BYTES",
    "AEGIS_V2_MIGRATION_OBJECTS",
    "AEGIS_V2_EPSS_PLAN_APPROVAL",
    "AEGIS_V2_EPSS_PLAN_USD",
    "AEGIS_V2_ONE_TIME_BUDGET_USD",
    "AEGIS_V2_HISTORY_APPROVAL",
    "AEGIS_V2_HISTORY_USD",
)


def project_environment(path: Path = ROOT / ".env") -> dict[str, str]:
    try:
        with path.open(encoding="utf-8") as stream:
            mode = os.fstat(stream.fileno()).st_mode
            if not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o600:
                raise DataError("root .env must be a regular file with permissions 600")
            values = dotenv_values(stream=stream, interpolate=False)
    except FileNotFoundError:
        values = {}
    return {
        name: value
        for name in PROJECT_OPTIONS
        if (value := os.environ.get(name, values.get(name))) is not None
    }


def configured_snapshot(environment: dict[str, str]) -> UUID | None:
    if snapshot := environment.get("AEGIS_SNAPSHOT"):
        try:
            return UUID(snapshot)
        except ValueError:
            raise DataError("AEGIS_SNAPSHOT must be a run UUID") from None
    return None
