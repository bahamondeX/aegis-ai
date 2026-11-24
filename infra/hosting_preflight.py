"""Authorize and verify the account before any future hosted pilot write."""

from decimal import Decimal, InvalidOperation

from infra.settings import Settings
from pipelines.config import project_environment
from pipelines.io import DataError


def hosting_budget(settings: Settings, env: dict[str, str]) -> Decimal:
    scope = f"{settings.account}/{settings.region}/{settings.project}/hosting"
    if env.get("AEGIS_HOSTING_APPROVAL") != scope:
        raise DataError("separate project-scoped hosting authorization is required")
    try:
        ceiling = Decimal(env.get("AEGIS_HOSTING_BUDGET_USD", ""))
    except InvalidOperation as error:
        raise DataError("enter the separate hosting ceiling from the authorization") from error
    if not ceiling.is_finite() or ceiling <= 0:
        raise DataError("the separate hosting ceiling must be finite and positive")
    return ceiling


def main() -> None:
    env = project_environment()
    settings = Settings.load(environment=env)
    ceiling = hosting_budget(settings, env)
    settings.identity()
    print(f"Hosting authorization and STS target verified. USD ceiling {ceiling}.")


if __name__ == "__main__":
    try:
        main()
    except DataError as error:
        raise SystemExit(str(error)) from error
