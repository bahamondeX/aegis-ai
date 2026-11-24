import gzip
import json
import logging
import os
import random
import stat
import time
from collections.abc import Callable
from datetime import UTC, date, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit
from uuid import uuid4

import httpx
import polars as pl
from dotenv import dotenv_values
from pydantic import ValidationError

from pipelines.io import DataError, capture_for, digest, read_raw, snapshot_directory, write_json
from pipelines.parse import parse_epss, parse_kev, parse_nvd
from schemas.sources import Attempt, Capture, KevCatalog, Run, Source

CISA = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS = "https://epss.cyentia.com/epss_scores-current.csv.gz"
EPSS_CURRENT = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SHODAN_INFO = "https://api.shodan.io/api-info"
SHODAN_COUNT = "https://api.shodan.io/shodan/host/count"
LICENSES: dict[Source, str] = {
    "cisa": "CC0-1.0 for the KEV catalog; third-party links have separate terms",
    "epss": "Public daily scores; attribute FIRST EPSS SIG and Empirical Security",
    "nvd": "NIST public data; include NVD non-endorsement notice",
    "shodan": "Provider terms; private capability status only",
}

MAX_BYTES = 16 * 1024 * 1024
MAX_ATTEMPTS = 3
NVD_INTERVAL = 6.2
PARSE_ERRORS = (DataError, ValueError, EOFError, gzip.BadGzipFile, pl.exceptions.PolarsError)


def credentials(path: Path) -> tuple[str | None, str | None]:
    names = ("NVD_API_KEY", "SHODAN_API_KEY")
    if all(name in os.environ for name in names) or not path.is_file():
        nvd, shodan = (os.getenv(name) or None for name in names)
        return nvd, shodan
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise DataError("dotenv permissions must be 600")
    values = dotenv_values(path, interpolate=False)
    nvd, shodan = (os.environ.get(name, values.get(name)) or None for name in names)
    return nvd, shodan


def retry_after(value: str | None) -> float:
    if not value:
        return 0
    try:
        if value.isdecimal():
            return float(int(value))
        return max(0, (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return 0


def request(
    client: httpx.Client,
    source: Source,
    uri: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    follow_redirects: bool = False,
) -> tuple[Capture, bytes | None]:
    attempts = []
    for index in range(MAX_ATTEMPTS):
        attempt = Attempt(fetched_at=datetime.now(UTC))
        data = None
        retryable = False
        try:
            with client.stream(
                "GET", uri, headers=headers, params=params, follow_redirects=follow_redirects
            ) as response:
                attempt.http_status = response.status_code
                if follow_redirects and response.history:
                    target = urlsplit(str(response.url))
                    attempt.final_uri = urlunsplit(
                        (
                            target.scheme,
                            target.netloc.rsplit("@", 1)[-1],
                            target.path,
                            "",
                            "",
                        )
                    )
                if response.status_code == 200:
                    buffer = bytearray()
                    deadline = time.monotonic() + 30
                    for chunk in response.iter_bytes(chunk_size=65536):
                        buffer.extend(chunk)
                        if len(buffer) > MAX_BYTES or time.monotonic() > deadline:
                            raise DataError("response_limit")
                    data = bytes(buffer)
                else:
                    attempt.error_code = f"http_{response.status_code}"
                    retryable = response.status_code == 429 or 500 <= response.status_code <= 599
                    if retryable:
                        attempt.retry_after_seconds = retry_after(
                            response.headers.get("Retry-After")
                        )
        except httpx.TransportError as error:
            attempt.error_code = type(error).__name__
            retryable = True
        except (DataError, httpx.DecodingError, httpx.TooManyRedirects):
            attempt.error_code = "invalid_or_oversized_response"
        attempt.fetched_at = datetime.now(UTC)
        attempts.append(attempt)
        if not retryable or index == MAX_ATTEMPTS - 1:
            break
        delay = max(
            attempt.retry_after_seconds or 0,
            NVD_INTERVAL if source == "nvd" else 0,
            2**index + random.uniform(0, 0.5),
        )
        if delay > 30:
            break
        time.sleep(delay)
    return Capture(
        source=source,
        uri=uri,
        license=LICENSES[source],
        attempts=attempts,
        error_code=attempts[-1].error_code,
    ), data


def archive(folder: Path, capture: Capture, body: bytes, suffix: str) -> None:
    name = f"{len(list((folder / 'raw').iterdir())):02d}-{capture.source}.{suffix}"
    (folder / "raw" / name).write_bytes(body)
    capture.raw_file = name
    capture.checksum = digest(body)


def public_feed(
    client: httpx.Client, folder: Path, source: Source, uri: str
) -> tuple[Capture, KevCatalog | pl.DataFrame | None]:
    outcome, content = request(client, source, uri, follow_redirects=True)
    if content is None:
        return outcome, None
    archive(folder, outcome, content, "json" if source == "cisa" else "csv.gz")
    try:
        if source == "cisa":
            catalog = parse_kev(content)
            outcome.source_date = catalog.dateReleased
            outcome.source_version = catalog.catalogVersion
            return outcome, catalog
        published, version, rows = parse_epss(content)
        outcome.source_date = published
        outcome.source_version = version
        return outcome, rows
    except PARSE_ERRORS:
        outcome.error_code = "source_schema"
        return outcome, None


def next_cohort(
    candidates: list[tuple[str, date]],
    scores: dict[str, float],
    cursor: list[str],
    limit: int,
) -> tuple[list[str], list[str]]:
    ranked = sorted(
        candidates,
        key=lambda entry: (-entry[1].toordinal(), -scores.get(entry[0], -1), entry[0]),
    )
    ids = [cve for cve, _ in ranked]
    seen = set(cursor) & set(ids)
    pending = [cve for cve in ids if cve not in seen]
    return (pending[:limit], sorted(seen)) if pending else (ids[:limit], [])


def check_shodan(client: httpx.Client, folder: Path, key: str | None) -> tuple[list[Capture], str]:
    if not key:
        return [], "missing_optional_credentials"

    info, body = request(client, "shodan", SHODAN_INFO, params={"key": key})
    if body is None:
        return [info], "account_check_failed"
    try:
        payload = json.loads(body)
        plan = payload.get("plan") if isinstance(payload, dict) else None
        # Only explicit free-plan labels opt into the credit-free count endpoint.
        free_plan = isinstance(plan, str) and plan.casefold() in {"free", "dev"}
        archive(folder, info, json.dumps({"free_plan": free_plan}).encode(), "json")
        if not isinstance(plan, str):
            info.error_code = "source_schema"
            return [info], "plan_unconfirmed"
    except (ValueError, UnicodeError):
        info.error_code = "source_schema"
        return [info], "plan_unconfirmed"
    if not free_plan:
        return [info], "free_plan_unconfirmed"

    count, body = request(
        client,
        "shodan",
        SHODAN_COUNT,
        params={"key": key, "query": "http", "facets": "country:1"},
    )
    if body is None:
        return [info, count], "aggregate_probe_failed"
    try:
        payload = json.loads(body)
        facets = payload.get("facets") if isinstance(payload, dict) else None
        country_facet = isinstance(facets, dict) and bool(facets.get("country"))
        archive(folder, count, json.dumps({"country_facet": country_facet}).encode(), "json")
    except (ValueError, UnicodeError):
        count.error_code = "source_schema"
        return [info, count], "aggregate_probe_invalid"
    return [info, count], (
        "generic_country_facet_only" if country_facet else "country_facet_unavailable"
    )


def run_capture(
    root: Path,
    previous: Run | None,
    limit: int,
    env_file: Path,
    *,
    daily_epss: bool = False,
    source_keys: tuple[str | None, str | None] | None = None,
) -> tuple[Path, Run]:
    nvd_key, shodan_key = credentials(env_file) if source_keys is None else source_keys
    started = datetime.now(UTC)
    run_id = uuid4()
    folder = snapshot_directory(root, run_id)
    (folder / "raw").mkdir(parents=True, mode=0o700)
    captures: list[Capture] = []
    durations: dict[Source, int] = {}
    # Keep authenticated URLs out of third-party library logs.
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.CRITICAL + 1)

    def collect[T](source: Source, work: Callable[[], T]) -> T:
        start = time.monotonic()
        try:
            return work()
        finally:
            durations[source] = round((time.monotonic() - start) * 1000)

    with httpx.Client(timeout=httpx.Timeout(12, connect=6), max_redirects=4) as client:

        def feed(source: Source, primary: str, fallback: str) -> KevCatalog | pl.DataFrame | None:
            capture, result = public_feed(client, folder, source, primary)
            captures.append(capture)
            if result is None:
                capture, result = public_feed(client, folder, source, fallback)
                captures.append(capture)
            return result

        kev = collect("cisa", lambda: feed("cisa", CISA, CISA_MIRROR))
        history = list(previous.nvd_history) if previous else []
        epss_history = dict(previous.epss_history) if previous else {}
        reuse = epss_history.get(started.date()) if daily_epss else None

        def scores_for_run() -> KevCatalog | pl.DataFrame | None:
            if reuse is None:
                return feed("epss", EPSS, EPSS_CURRENT)
            original = snapshot_directory(root, reuse)
            archived = Run.model_validate_json((original / "capture.json").read_bytes())
            capture = capture_for(archived.captures, "epss")
            if capture is None or capture.raw_file is None:
                raise DataError("epss: scheduled reuse is missing its original capture")
            body = read_raw(original, capture)
            (folder / "raw" / capture.raw_file).write_bytes(body)
            captures.append(capture)
            return parse_epss(body)[2]

        epss = collect("epss", scores_for_run)
        cursor = list(previous.cursor) if previous else []
        requested: list[str] = []
        found: list[str] = []

        if isinstance(kev, KevCatalog) and isinstance(epss, pl.DataFrame):
            scores = dict(epss.select("cve", "epss").iter_rows())
            requested, cycle = next_cohort(
                [(record.cveID, record.dateAdded) for record in kev.vulnerabilities],
                scores,
                cursor,
                limit,
            )
            query = urlencode({"cveIds": ",".join(requested), "resultsPerPage": limit})
            # One page per run. Space it from any previous run under the writer lock.
            time.sleep(NVD_INTERVAL)
            outcome, body = collect(
                "nvd",
                lambda: request(
                    client,
                    "nvd",
                    f"{NVD}?{query}",
                    headers={"apiKey": nvd_key} if nvd_key else None,
                ),
            )
            captures.append(outcome)
            if body is not None:
                archive(folder, outcome, body, "json")
                try:
                    nvd, records = parse_nvd(body, requested)
                    outcome.source_date = nvd.timestamp
                    outcome.source_version = nvd.version
                    found = sorted(records)
                    cursor = sorted(set(cycle) | set(requested))
                    if found:
                        history.append(run_id)
                except (DataError, ValidationError):
                    outcome.error_code = "source_schema"

        shodan, shodan_status = collect("shodan", lambda: check_shodan(client, folder, shodan_key))
        captures.extend(shodan)
        epss_capture = capture_for(captures, "epss")
        if reuse is None and epss_capture is not None and epss_capture.source_date is not None:
            epss_history[epss_capture.source_date.date()] = run_id

    result = Run(
        run_id=run_id,
        started_at=started,
        finished_at=datetime.now(UTC),
        captures=captures,
        requested_nvd=requested,
        nvd_found=found,
        cursor=cursor,
        nvd_history=history,
        epss_history=epss_history,
        shodan_status=shodan_status,
        durations_ms=durations,
    )
    write_json(folder / "capture.json", result)
    return folder, result
