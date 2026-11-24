import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import polars as pl
import pyarrow as pa

from pipelines.io import DataError, capture_for, digest, read_raw, snapshot_directory
from pipelines.parse import parse_epss, parse_kev, parse_nvd
from schemas.sources import Capture, NvdConfiguration, NvdRecord, Run, Source
from schemas.tables import GRAINS, TABLES

Row = dict[str, Any]
CWE_ID = re.compile(r"CWE-[0-9]+")
CPE_PART = re.compile(r"(?:\\.|[^:\\])+")


def identity(*values: str) -> str:
    return digest(json.dumps(values, ensure_ascii=False).encode())


def clean_name(value: str) -> str:
    return " ".join(value.casefold().split())


def cpe_product(criteria: str) -> tuple[str, str]:
    parts = CPE_PART.findall(criteria)
    if len(parts) != 13 or ":".join(parts) != criteria or parts[:2] != ["cpe", "2.3"]:
        raise DataError("nvd: malformed CPE 2.3 criterion")
    vendor, product = (clean_name(re.sub(r"\\(.)", r"\1", part)) for part in parts[3:5])
    return vendor, product


def required_capture(run: Run, source: Source) -> Capture:
    capture = capture_for(run.captures, source)
    if capture is None or capture.error_code is not None or capture.source_date is None:
        error = capture.error_code if capture is not None else "missing_capture"
        raise DataError(f"{source}: {error}")
    return capture


def evidence_row(
    run_id: UUID, capture: Capture, record_id: str, source_date: datetime | None = None
) -> Row:
    checksum, raw_file = capture.checksum, capture.raw_file
    source_date = source_date or capture.source_date
    if checksum is None or raw_file is None or source_date is None:
        raise DataError(f"{capture.source}: incomplete evidence")
    evidence_id = identity(
        capture.source, checksum, capture.uri, record_id, capture.retrieved_at.isoformat()
    )
    return {
        "evidence_id": evidence_id,
        "source": capture.source,
        "source_record_id": record_id,
        "retrieved_at": capture.retrieved_at,
        "source_date": source_date,
        "checksum": checksum,
        "uri": capture.uri,
        "license": capture.license,
        "raw_snapshot": str(run_id),
        "raw_file": raw_file,
    }


def nvd_history(root: Path, run: Run) -> dict[str, tuple[NvdRecord, Row]]:
    enriched: dict[str, tuple[NvdRecord, Row]] = {}
    for run_id in run.nvd_history:
        folder = snapshot_directory(root, run_id)
        archived = (
            run
            if run_id == run.run_id
            else Run.model_validate_json((folder / "capture.json").read_bytes())
        )
        capture = required_capture(archived, "nvd")
        _, records = parse_nvd(read_raw(folder, capture), archived.requested_nvd)
        for cve_id, record in records.items():
            previous = enriched.get(cve_id)
            if previous is None or previous[0].lastModified <= record.lastModified:
                enriched[cve_id] = (
                    record,
                    evidence_row(run_id, capture, cve_id, record.lastModified),
                )
    return enriched


def add_product(
    products: dict[str, Row], source: Source, vendor: str, product: str, cpe: str | None = None
) -> str:
    product_id = identity(source, vendor, product, cpe or "")
    products[product_id] = {
        "product_id": product_id,
        "vendor": vendor,
        "product": product,
        "cpe": cpe,
        "source": source,
    }
    return product_id


def nvd_relationships(
    record: NvdRecord, ref: str, products: dict[str, Row]
) -> tuple[list[Row], list[Row]]:
    by_product: defaultdict[str, list[str]] = defaultdict(list)
    for conf_index, raw_config in enumerate(record.configurations):
        config = NvdConfiguration.model_validate(raw_config)
        for node_index, node in enumerate(config.nodes):
            for match_index, match in enumerate(node.cpeMatch):
                vendor, product = cpe_product(match.criteria)
                product_id = add_product(products, "nvd", vendor, product, match.criteria)
                pointer = f"/configurations/{conf_index}/nodes/{node_index}/cpeMatch/{match_index}"
                by_product[product_id].append(pointer)
    product_links = [
        {
            "cve_id": record.id,
            "product_id": product_id,
            "evidence_id": ref,
            "relation_type": "nvd_cpe_match",
            "configuration_refs": pointers,
        }
        for product_id, pointers in by_product.items()
    ]
    by_cwe: defaultdict[str, set[str]] = defaultdict(set)
    for weak in record.weaknesses:
        for description in weak.description:
            if CWE_ID.fullmatch(description.value):
                by_cwe[description.value].add(weak.source)
    cwe_links = [
        {
            "cve_id": record.id,
            "cwe_id": cwe,
            "evidence_id": ref,
            "source": "nvd",
            "attributed_to": sorted(sources),
        }
        for cwe, sources in by_cwe.items()
    ]
    return product_links, cwe_links


def epss_evidence(folder: Path, run: Run) -> Row:
    capture = required_capture(run, "epss")
    read_raw(folder, capture)
    if capture.source_date is None or capture.source_version is None:
        raise DataError("epss: missing score date or model version")
    return evidence_row(
        run.run_id, capture, f"{capture.source_date.date()}/{capture.source_version}"
    )


def make_runs(run: Run, cohort_size: int, epss_count: int, overlap: int) -> list[Row]:
    counts = {"cisa": cohort_size, "epss": epss_count, "nvd": len(run.nvd_found), "shodan": 0}
    coverage = {
        "cisa": 1.0,
        "epss": overlap / cohort_size,
        "nvd": len(run.nvd_found) / len(run.requested_nvd),
        "shodan": None,
    }
    rows = []
    for source in ("cisa", "epss", "nvd", "shodan"):
        capture = capture_for(run.captures, source)
        err = capture.error_code if capture else None
        if source == "shodan":
            status = "unavailable"
            error_code = run.shodan_status
        elif source == "nvd" and not run.nvd_found:
            status = "blocked"
            error_code = err or "no_records"
        elif source == "nvd" and len(run.nvd_found) < len(run.requested_nvd):
            status = "partial"
            error_code = "missing_records"
        else:
            status = "ok"
            error_code = None
        rows.append(
            {
                "run_id": str(run.run_id),
                "source": source,
                "status": status,
                "row_count": counts[source],
                "coverage": coverage[source],
                "cursor": run.cursor if source == "nvd" else None,
                "duration_ms": run.durations_ms.get(source, 0),
                "error_code": error_code,
                "source_date": capture.source_date if capture else None,
                "retrieved_at": capture.retrieved_at if capture else None,
            }
        )
    return rows


def normalize(root: Path, folder: Path, run: Run) -> dict[str, pa.Table]:
    kev_capture = required_capture(run, "cisa")
    catalog = parse_kev(read_raw(folder, kev_capture))
    epss_capture = required_capture(run, "epss")
    published, version, epss = parse_epss(read_raw(folder, epss_capture))
    score_date = published.date()
    score_run = run.epss_history[score_date]
    score_evidence = evidence_row(score_run, epss_capture, f"{score_date}/{version}")
    evidence = [score_evidence]
    for run_id in sorted(set(run.epss_history.values()) - {score_run}, key=str):
        archived_folder = snapshot_directory(root, run_id)
        archived = Run.model_validate_json((archived_folder / "capture.json").read_bytes())
        evidence.append(epss_evidence(archived_folder, archived))
    facts = (
        epss.rename({"cve": "cve_id"})
        .with_columns(
            pl.lit(score_date, dtype=pl.Date).alias("score_date"),
            pl.lit(score_evidence["evidence_id"]).alias("source_ref"),
        )
        .select(TABLES["fact_epss"].names)
        .sort("cve_id")
        .to_arrow()
        .cast(TABLES["fact_epss"])
    )
    product_links: list[Row] = []
    cwe_links: list[Row] = []
    products: dict[str, Row] = {}
    cves: list[Row] = []
    enriched = nvd_history(root, run)
    for entry in catalog.vulnerabilities:
        cve_id = entry.cveID
        kev_record = evidence_row(run.run_id, kev_capture, cve_id)
        kev_ref = kev_record["evidence_id"]
        evidence.append(kev_record)
        source_refs = [kev_ref]
        product_id = add_product(
            products, "cisa", clean_name(entry.vendorProject), clean_name(entry.product)
        )
        product_links.append(
            {
                "cve_id": cve_id,
                "product_id": product_id,
                "evidence_id": kev_ref,
                "relation_type": "kev_catalog_product",
                "configuration_refs": None,
            }
        )
        cwe_links.extend(
            {
                "cve_id": cve_id,
                "cwe_id": cwe,
                "evidence_id": kev_ref,
                "source": "cisa",
                "attributed_to": ["CISA"],
            }
            for cwe in sorted(set(entry.cwes))
            if CWE_ID.fullmatch(cwe)
        )
        record = None
        if cve_id in enriched:
            record, nvd_record = enriched[cve_id]
            evidence.append(nvd_record)
            ref = nvd_record["evidence_id"]
            source_refs.append(ref)
            nvd_products, nvd_cwes = nvd_relationships(record, ref, products)
            product_links.extend(nvd_products)
            cwe_links.extend(nvd_cwes)
        metric = record.metrics.preferred() if record else None
        description = (
            next(
                (text.value for text in record.descriptions if text.lang == "en"),
                entry.shortDescription,
            )
            if record
            else entry.shortDescription
        )
        severity = (metric.cvssData.baseSeverity or metric.baseSeverity) if metric else None
        cves.append(
            {
                "cve_id": cve_id,
                "description": description,
                "published_at": record.published if record else None,
                "modified_at": record.lastModified if record else None,
                "cvss_score": metric.cvssData.baseScore if metric else None,
                "cvss_version": metric.cvssData.version if metric else None,
                "cvss_source": metric.source if metric else None,
                "cvss_vector": metric.cvssData.vectorString if metric else None,
                "severity": severity.upper() if severity else None,
                "kev": True,
                "kev_added_at": entry.dateAdded,
                "kev_due_at": entry.dueDate,
                "kev_ransomware_use": entry.knownRansomwareCampaignUse,
                "source_refs": source_refs,
                "nvd_configurations_json": (
                    json.dumps(record.configurations, sort_keys=True, separators=(",", ":"))
                    if record and "configurations" in record.model_fields_set
                    else None
                ),
            }
        )
    overlap = len(set(epss["cve"]) & {row["cve_id"] for row in cves})
    rows_by_table = {
        "dim_cve": cves,
        "dim_product": list(products.values()),
        "bridge_cve_product": product_links,
        "bridge_cve_cwe": cwe_links,
        "fact_geo_exposure": [],
        "evidence": evidence,
        "ingestion_runs": make_runs(run, len(cves), epss.height, overlap),
    }
    tables = {
        name: pa.Table.from_pylist(
            sorted(rows, key=lambda row: tuple(row[column] for column in GRAINS[name])),
            schema=TABLES[name],
        )
        for name, rows in rows_by_table.items()
    }
    return {**tables, "fact_epss": facts}
