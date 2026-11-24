import os
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from re import fullmatch

import boto3
from botocore.config import Config

from pipelines.io import DataError

SDK_CONFIG = Config(
    connect_timeout=5,
    read_timeout=30,
    retries={"mode": "standard", "total_max_attempts": 3},
)
SECRET_KEYS = ("NVD_API_KEY", "SHODAN_API_KEY")
SCAN_CUTOFF = 64 * 1024 * 1024
LAMBDA_TIMEOUT = 540


@dataclass(frozen=True)
class Settings:
    account: str
    region: str
    profile: str
    project: str
    schedule_enabled: bool

    @classmethod
    def load(cls, *, offline: bool = False) -> "Settings":
        account = os.getenv("AEGIS_AWS_ACCOUNT") or ("000000000000" if offline else "")
        region = os.getenv("AEGIS_AWS_REGION") or ("us-east-1" if offline else "")
        profile = os.getenv("AEGIS_AWS_PROFILE") or ""
        project = os.getenv("AEGIS_PROJECT_PREFIX", "aegis-dev")
        schedule = os.getenv("AEGIS_SCHEDULE_ENABLED", "0")
        if not fullmatch(r"[0-9]{12}", account) or not fullmatch(
            r"[a-z]{2}(-[a-z0-9]+)+-\d", region
        ):
            raise DataError("set AEGIS_AWS_ACCOUNT and AEGIS_AWS_REGION for the project")
        if not offline and (not profile or account == "000000000000"):
            raise DataError("set AEGIS_AWS_PROFILE and a real AEGIS_AWS_ACCOUNT for the project")
        if not fullmatch(r"aegis-[a-z0-9-]{2,18}[a-z0-9]", project) or schedule not in ("0", "1"):
            raise DataError("invalid project prefix or AEGIS_SCHEDULE_ENABLED")
        return cls(account, region, profile, project, schedule == "1")

    @property
    def stack(self) -> str:
        return f"{self.project}-lake"

    @property
    def database(self) -> str:
        return self.project.replace("-", "_")

    @property
    def secret_path(self) -> str:
        return "/aegis/dev"

    def identity(self) -> tuple[boto3.Session, str]:
        session = boto3.Session(profile_name=self.profile, region_name=self.region)
        identity = session.client("sts", config=SDK_CONFIG).get_caller_identity()
        if identity["Account"] != self.account:
            raise DataError("STS account does not match AEGIS_AWS_ACCOUNT")
        return session, identity["Arn"]

    def authorize(self) -> Decimal:
        if os.getenv("AEGIS_DEPLOY_APPROVAL") != f"{self.account}/{self.region}/{self.project}":
            raise DataError(
                "explicit AEGIS_DEPLOY_APPROVAL for this account, region and prefix is required"
            )
        try:
            budget = Decimal(os.getenv("AEGIS_BUDGET_USD", ""))
        except InvalidOperation:
            raise DataError("set AEGIS_BUDGET_USD to the explicitly approved USD ceiling") from None
        if not budget.is_finite() or budget <= 0:
            raise DataError("AEGIS_BUDGET_USD must be finite and positive")
        return budget
