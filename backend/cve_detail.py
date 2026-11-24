"""Source-bound CVE detail and mitigation projection over a pinned release."""

import json
from typing import TYPE_CHECKING
from uuid import UUID

from botocore.exceptions import BotoCoreError, ClientError
from pydantic import ValidationError

from backend.models import (
    Advisory,
    Applicability,
    CveDetail,
    Filters,
    ServiceError,
    Vulnerability,
)
from pipelines.io import DataError, digest
from pipelines.normalize import CPE_PART, cpe_product
from schemas.sources import KevCatalog, NvdConfiguration

if TYPE_CHECKING:
    from backend.reader import SnapshotReader


def guidance(reader: "SnapshotReader", cve: str, identifier: str) -> Advisory | None:
    if reader.cisa_archive is None:
        return None
    source = reader.table("evidence")
    rows = reader.rows(
        "SELECT raw_snapshot, raw_file, checksum "
        f"FROM {source} WHERE evidence_id=? AND source='cisa' AND source_record_id=? LIMIT 1",
        [identifier, cve],
        1,
    )
    if not rows:
        return None
    row = rows[0]
    expected = f"snapshots/{reader.snapshot}/raw/00-cisa.json"
    actual = f"snapshots/{row['raw_snapshot']}/raw/{row['raw_file']}"
    if actual != expected:
        raise ServiceError("archive_mismatch", "catalog evidence is outside the release", 503)
    try:
        catalog = reader.archived_kev
        if catalog is None:
            return None
        if digest(catalog) != row["checksum"]:
            raise DataError("catalog checksum differs")
        record = next(
            (
                item
                for item in KevCatalog.model_validate_json(catalog).vulnerabilities
                if item.cveID == cve
            ),
            None,
        )
    except (OSError, DataError, ValidationError, BotoCoreError, ClientError) as error:
        raise ServiceError(
            "archive_unavailable", "unable to verify archived guidance", 503
        ) from error
    if record is None or not record.requiredAction:
        return None
    text = " ".join(record.requiredAction.split())
    if not text or len(text) > 600:
        return None
    return Advisory(text=text, evidence_id=identifier, source="cisa")


def detail(reader: "SnapshotReader", cve: str, snapshot_id: UUID, country: str | None) -> CveDetail:
    from backend.reader import View

    if snapshot_id != reader.snapshot:
        raise ServiceError(
            "snapshot_mismatch", "refresh and reselect the CVE in the current release", 409
        )
    selection = Filters(cve_ids=(cve,), limit=1)
    matches = reader.view_rows(View.CVES, selection, Vulnerability)
    if not matches:
        raise ServiceError("not_found", "CVE is outside this release", 404)
    row = matches[0]
    evidence_ids = tuple(dict.fromkeys(filter(None, (*row.source_refs, row.epss_evidence_id))))
    evidence = [reader.evidence(identifier).data for identifier in evidence_ids[:4]]
    cisa = next(
        (item for item in evidence if item.source == "cisa" and item.source_record_id == cve), None
    )
    nvd = next(
        (item for item in evidence if item.source == "nvd" and item.source_record_id == cve), None
    )
    selection = selection.model_copy(update={"limit": 20})
    products = [
        item
        for item in reader.graph(selection).data
        if item.relation_type == "kev_catalog_product"
        and cisa
        and item.evidence_id == cisa.evidence_id
    ]
    applicable = []
    if nvd:
        config = reader.rows(
            f"SELECT nvd_configurations_json FROM {reader.table('dim_cve')} WHERE cve_id=? LIMIT 1",
            [cve],
            1,
        )
        raw = config[0]["nvd_configurations_json"]
        if raw is not None:
            for i, item in enumerate(json.loads(raw)):
                for j, node in enumerate(NvdConfiguration.model_validate(item).nodes):
                    for k, match in enumerate(node.cpeMatch):
                        if not match.vulnerable:
                            continue
                        vendor, product = cpe_product(match.criteria)
                        version = CPE_PART.findall(match.criteria)[5]
                        applicable.append(
                            Applicability(
                                vendor=vendor,
                                product=product,
                                version=None if version in {"*", "-"} else version,
                                start_including=match.versionStartIncluding,
                                start_excluding=match.versionStartExcluding,
                                end_including=match.versionEndIncluding,
                                end_excluding=match.versionEndExcluding,
                                configuration_path=f"/configurations/{i}/nodes/{j}/cpeMatch/{k}",
                                evidence_id=nvd.evidence_id,
                            )
                        )
                        if len(applicable) == 20:
                            break
                    if len(applicable) == 20:
                        break
                if len(applicable) == 20:
                    break
    geo = reader.geography(Filters(cve_ids=(cve,), country_iso2=country, limit=20))
    return CveDetail(
        snapshot_id=reader.snapshot,
        vulnerability=row,
        products=products,
        applicability=applicable,
        evidence=evidence,
        geography=geo.exposure,
        observations=geo.data,
        mitigation=guidance(reader, cve, cisa.evidence_id) if cisa else None,
    )
