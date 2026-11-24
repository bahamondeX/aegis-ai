"""Converse preferences over fixed evidence claims, with a separate spending guard."""

import asyncio
import json
import random
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from email.utils import parsedate_to_datetime
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, ConnectTimeoutError, ReadTimeoutError
from langchain_aws import ChatBedrockConverse
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from backend.investigations.contracts import Claim, Usage
from backend.investigations.store import Store, reserve
from backend.models import ServiceError
from infra.settings import SDK_CONFIG, Settings

MAX_ATTEMPTS = 3
MAX_OUTPUT_TOKENS = 256
MAX_INPUT_ESTIMATE = 4096
TOKENS_PER_MILLION = Decimal("1000000")
TRANSIENT = {
    "ThrottlingException",
    "TooManyRequestsException",
    "ModelTimeoutException",
    "ServiceUnavailableException",
    "InternalServerException",
    "ModelNotReadyException",
}
SYSTEM = (
    "Select up to six emphasis keys from the provided fact list. "
    'Return only one JSON object shaped as {"keys":["VERBATIM_KEY"]}. '
    "Use only the keys supplied. Do not create prose, instructions, or new facts."
)
SDK_INFERENCE = Config(
    connect_timeout=2, read_timeout=7, retries={"mode": "standard", "total_max_attempts": 1}
)


class ModelSelection(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    keys: list[str] = Field(min_length=1, max_length=6)


@dataclass(frozen=True)
class Preference:
    selection: ModelSelection | None
    usage: Usage


Select = Callable[[list[Claim]], Awaitable[Preference]]


def model_available(session: boto3.Session, model_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z][a-z0-9_-]*\.[a-z0-9.:-]{1,100}", model_id):
        raise ValueError("configure an in-region foundation model ID")
    control = session.client("bedrock", config=SDK_CONFIG)
    details = control.get_foundation_model(modelIdentifier=model_id)["modelDetails"]
    access = control.get_foundation_model_availability(modelId=model_id)
    if (
        details["modelLifecycle"]["status"] != "ACTIVE"
        or "ON_DEMAND" not in details["inferenceTypesSupported"]
        or "TEXT" not in details["inputModalities"]
        or "TEXT" not in details["outputModalities"]
        or access["regionAvailability"] != "AVAILABLE"
        or access["authorizationStatus"] != "AUTHORIZED"
        or access["entitlementAvailability"] != "AVAILABLE"
        or access["agreementAvailability"]["status"] != "AVAILABLE"
    ):
        raise ValueError("configured model is not available for in-region text inference")
    return {
        "model_id": details["modelId"],
        "region": session.region_name,
        "availability": "verified",
    }


def read_amount(environment: dict[str, str], name: str) -> Decimal:
    try:
        value = Decimal(environment.get(name, ""))
    except InvalidOperation:
        raise ValueError(f"configure {name}") from None
    if not value.is_finite() or value <= 0:
        raise ValueError(f"{name} must be finite and positive")
    return value


def approved_model(environment: dict[str, str], store: Store) -> Select:
    settings = Settings.load(environment=environment)
    scope = f"{settings.account}/{settings.region}/{settings.project}/bedrock"
    if environment.get("AEGIS_BEDROCK_APPROVAL") != scope:
        raise ValueError(
            "a separate Bedrock approval scoped to this account and region is required"
        )
    ceiling, _ = bedrock_allocations(environment)
    in_rate = read_amount(environment, "AEGIS_BEDROCK_INPUT_USD_PER_MILLION")
    out_rate = read_amount(environment, "AEGIS_BEDROCK_OUTPUT_USD_PER_MILLION")
    session, _ = settings.identity()
    model_id = environment.get("BEDROCK_MODEL_ID", "")
    model_available(session, model_id)
    return make_selector(session, model_id, store, ceiling, in_rate, out_rate)


def bedrock_allocations(environment: dict[str, str]) -> tuple[Decimal, Decimal]:
    ceiling = read_amount(environment, "AEGIS_BEDROCK_TOTAL_BUDGET_USD")
    local = read_amount(environment, "AEGIS_BEDROCK_BUDGET_USD")
    runtime = read_amount(environment, "AEGIS_BEDROCK_RUNTIME_BUDGET_USD")
    if local + runtime > ceiling:
        raise ValueError("local and runtime Bedrock allocations exceed the shared ceiling")
    return local, runtime


def transient(error: Exception) -> tuple[bool, float]:
    if isinstance(error, (ConnectTimeoutError, ReadTimeoutError)):
        return True, 0
    if isinstance(error, ClientError):
        metadata = error.response.get("ResponseMetadata", {})
        code = error.response.get("Error", {}).get("Code")
        status = metadata.get("HTTPStatusCode", 0)
        header = metadata.get("HTTPHeaders", {}).get("retry-after")
        wait = 0.0
        if isinstance(header, str):
            if header.isascii() and header.isdecimal():
                wait = float(header)
            else:
                try:
                    date = parsedate_to_datetime(header)
                    if date.tzinfo is not None:
                        wait = max(0.0, (date - datetime.now(UTC)).total_seconds())
                except (TypeError, ValueError, OverflowError):
                    pass
        return code in TRANSIENT or status == 429 or 500 <= status <= 599, wait
    return False, 0


async def retry[T](
    invoke: Callable[[], Awaitable[T]],
    *,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    jitter: Callable[[float, float], float] = random.uniform,
) -> tuple[T, int]:
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return await invoke(), attempt
        except (ClientError, ConnectTimeoutError, ReadTimeoutError) as error:
            recover, wait = transient(error)
            if not recover or attempt == MAX_ATTEMPTS or wait > 4:
                status = (
                    504
                    if isinstance(error, (ConnectTimeoutError, ReadTimeoutError))
                    or (
                        isinstance(error, ClientError)
                        and error.response.get("Error", {}).get("Code") == "ModelTimeoutException"
                    )
                    else 503
                )
                raise ServiceError("model_unavailable", "Bedrock request failed", status) from error
            await sleep(max(wait, jitter(0.2, 0.4 * 2 ** (attempt - 1))))
    raise AssertionError("bounded attempt loop did not terminate")


def parse_selection(content: object) -> ModelSelection | None:
    if not isinstance(content, str):
        if not isinstance(content, list) or any(
            not isinstance(block, dict)
            or block.get("type") != "text"
            or not isinstance(block.get("text"), str)
            for block in content
        ):
            return None
        content = "".join(block["text"] for block in content)
    if len(content) > 4096:
        return None
    try:
        return ModelSelection.model_validate_json(content)
    except ValidationError:
        return None


def make_selector(
    session: boto3.Session,
    model_id: str,
    store: Store,
    ceiling: Decimal,
    in_rate: Decimal,
    out_rate: Decimal,
) -> Select:
    client = session.client("bedrock-runtime", config=SDK_INFERENCE)
    model = ChatBedrockConverse(
        client=client,
        model=model_id,
        region_name=session.region_name,
        temperature=0,
        max_tokens=MAX_OUTPUT_TOKENS,
    )
    charge = (in_rate * MAX_INPUT_ESTIMATE + out_rate * MAX_OUTPUT_TOKENS) / TOKENS_PER_MILLION

    async def select(claims: list[Claim]) -> Preference:
        # All text is rendered from vetted numeric or enumerated facts. Raw feed
        # descriptions, reference text, and the caller's question never reach Bedrock.
        prompt = json.dumps(
            [{"key": item.key, "fact": item.text} for item in claims], ensure_ascii=True
        )
        if len(SYSTEM.encode()) + len(prompt.encode()) > MAX_INPUT_ESTIMATE - 512:
            raise ServiceError("model_input_limit", "model input exceeds its budget", 422)
        started = time.monotonic()

        async def attempt() -> Any:
            await asyncio.to_thread(reserve, store, "bedrock-spend", charge, ceiling)
            return await model.ainvoke([SystemMessage(SYSTEM), HumanMessage(prompt)])

        reply, attempts = await retry(attempt)
        usage = reply.usage_metadata or {}
        return Preference(
            selection=parse_selection(reply.content),
            usage=Usage(
                model_id=model_id,
                attempts=attempts,
                input_tokens=usage.get("input_tokens"),
                output_tokens=usage.get("output_tokens"),
                latency_ms=int((time.monotonic() - started) * 1000),
            ),
        )

    return select
