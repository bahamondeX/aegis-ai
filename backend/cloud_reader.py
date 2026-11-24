"""Shared encrypted, scan-capped Athena reader for a pinned cloud release."""

import json
from uuid import UUID

from boto3.session import Session

from backend.geography import NetworkContext, read_context
from backend.reader import SnapshotReader
from infra.settings import SCAN_CUTOFF, SDK_CONFIG, Settings
from pipelines.athena import AthenaReader
from pipelines.cloud import SnapshotStore
from pipelines.io import DataError


def pinned_reader(
    session: Session, settings: Settings, environment: dict[str, str]
) -> SnapshotReader:
    snapshot = UUID(environment["AEGIS_SNAPSHOT"])
    s3 = session.client("s3", config=SDK_CONFIG)
    archive = SnapshotStore(s3, environment["AEGIS_LAKE_BUCKET"])
    kms = environment["AEGIS_LAKE_KMS_ARN"]

    def read_cisa() -> bytes:
        data = archive.read(f"snapshots/{snapshot}/raw/00-cisa.json")
        if data is None or len(data) > 4 * 1024 * 1024:
            raise DataError("CISA archive is missing or exceeds its byte budget")
        return data

    release = archive.release(snapshot)
    manifest = archive.read(f"snapshots/{snapshot}/manifest.json")
    if release is None or manifest is None:
        raise DataError("runtime requires a pinned, validated cloud release")
    version = json.loads(manifest)
    if version["status"] != "ok" or UUID(version["run_id"]) != snapshot:
        raise DataError("release and snapshot manifest must agree")

    workgroup = settings.project
    athena = session.client("athena", config=SDK_CONFIG)
    group = athena.get_work_group(WorkGroup=workgroup)["WorkGroup"]
    config = group["Configuration"]
    result = config["ResultConfiguration"]
    if (
        group["State"] != "ENABLED"
        or not config.get("EnforceWorkGroupConfiguration")
        or not 0 < config.get("BytesScannedCutoffPerQuery", 0) <= SCAN_CUTOFF
        or result.get("OutputLocation") != f"s3://{environment['AEGIS_RESULTS_BUCKET']}/queries/"
        or result.get("EncryptionConfiguration") != {"EncryptionOption": "SSE_KMS", "KmsKey": kms}
    ):
        raise DataError("runtime requires the approved encrypted, scan-capped workgroup")
    network: tuple[NetworkContext, ...] = ()
    checksum = environment.get("AEGIS_NETWORK_CONTEXT_DIGEST")
    if checksum:
        blob = archive.read(f"control/network/{snapshot}/{checksum}.json")
        if blob is None:
            raise DataError("pinned network companion is missing")
        network = read_context(blob, checksum.encode(), snapshot)

    return SnapshotReader.cloud(
        AthenaReader(athena, settings.database, workgroup),
        release,
        geo_available=version["geometry"]["status"] == "available",
        cisa_archive=read_cisa,
        network=network,
    )
