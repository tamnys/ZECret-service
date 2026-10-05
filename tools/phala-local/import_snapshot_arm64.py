#!/usr/bin/env python3
"""Import the pinned unsigned public Testnet snapshot on native ARM64 Linux.

This prepares local public node data only. It does not approve a Phala image,
attestation policy, private query, or cloud deployment.
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "deploy/phala/snapshot-arm64-local.lock.json"
LOCK_SHA256 = "fd2a58c1f4b9f2fe52d0675fade0bdbafef5d40da21771f22fa7b99a3e445c1b"
SNAPSHOT_LOCK = ROOT / "deploy/phala/snapshot.lock.json"
IMPORTER = ROOT / "deploy/phala/image/snapshot_import.py"
WORKSPACE = Path("/workspace")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate lock field")
        result[key] = value
    return result


def load_lock():
    if LOCK.is_symlink() or not LOCK.is_file():
        raise ValueError("local ARM64 lock is not a regular file")
    data = LOCK.read_bytes()
    if digest(data) != LOCK_SHA256:
        raise ValueError("local ARM64 lock differs from reviewed bytes")
    value = json.loads(data, object_pairs_hook=unique_object)
    wheel = value.get("wheel") if isinstance(value, dict) else None
    if (set(value) != {"schema_version", "status", "source_snapshot_lock_sha256",
                       "source_importer_sha256", "archive_sha256",
                       "archive_size_bytes", "extracted_regular_file_bytes", "wheel",
                       "private_mode_approved", "cloud_deployment_approved"}
            or value["schema_version"] != 1
            or value["status"] != "local-unsigned-public-testnet-import-only"
            or value["private_mode_approved"] is not False
            or value["cloud_deployment_approved"] is not False
            or not isinstance(wheel, dict)
            or set(wheel) != {"package", "version", "pypi_metadata_url", "filename",
                              "url", "size_bytes", "sha256", "uploaded_at_utc"}
            or wheel["package"] != "zstandard"
            or wheel["version"] != "0.25.0"
            or not wheel["filename"].startswith("zstandard-0.25.0-cp313-cp313-")
            or "aarch64" not in wheel["filename"]
            or type(wheel["size_bytes"]) is not int or wheel["size_bytes"] <= 0):
        raise ValueError("local ARM64 lock is malformed or approving")
    if digest(SNAPSHOT_LOCK.read_bytes()) != value["source_snapshot_lock_sha256"]:
        raise ValueError("reviewed public snapshot lock changed")
    if digest(IMPORTER.read_bytes()) != value["source_importer_sha256"]:
        raise ValueError("reviewed snapshot importer changed")
    uploaded = datetime.fromisoformat(wheel["uploaded_at_utc"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) < uploaded + timedelta(days=7):
        raise ValueError("ARM64 decompressor wheel remains within release hold")
    return value


def workspace_dir(raw):
    path = Path(raw)
    if not path.is_absolute() or not path.is_relative_to(WORKSPACE):
        raise ValueError("work directory must be absolute under /workspace")
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_dir():
            raise ValueError("work directory is not a regular directory")
    else:
        if path.parent.resolve(strict=True) != path.parent:
            raise ValueError("work directory parent is a symlink")
        path.mkdir(mode=0o700)
    if path.resolve(strict=True) != path:
        raise ValueError("work directory traverses a symlink")
    return path


def official_wheel_metadata(wheel):
    with urllib.request.urlopen(wheel["pypi_metadata_url"], timeout=15) as response:
        metadata = json.load(response)
    matches = [item for item in metadata.get("urls", [])
               if item.get("filename") == wheel["filename"]]
    if (len(matches) != 1
            or matches[0].get("url") != wheel["url"]
            or matches[0].get("size") != wheel["size_bytes"]
            or matches[0].get("digests", {}).get("sha256") != wheel["sha256"]
            or matches[0].get("upload_time_iso_8601") != wheel["uploaded_at_utc"]
            or matches[0].get("packagetype") != "bdist_wheel"
            or matches[0].get("yanked") is not False):
        raise ValueError("official PyPI ARM64 wheel metadata changed")


def require_no_known_advisories(wheel):
    body = json.dumps({"package": {"name": wheel["package"], "ecosystem": "PyPI"},
                       "version": wheel["version"]}).encode()
    request = urllib.request.Request("https://api.osv.dev/v1/query", body,
                                     {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        report = json.load(response)
    if (not isinstance(report, dict) or "error" in report
            or report.get("vulns", []) != []):
        raise ValueError("ARM64 decompressor advisory check changed or failed")


def verified_wheel(work, wheel):
    destination = work / wheel["filename"]
    if destination.is_symlink():
        raise ValueError("ARM64 wheel cache is a symlink")
    if not destination.exists():
        request = urllib.request.Request(wheel["url"],
                                         headers={"User-Agent": "zrpc-local-testnet-import/1"})
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status != 200 or response.geturl() != wheel["url"]:
                raise ValueError("ARM64 wheel URL or HTTP status changed")
            content = response.read(wheel["size_bytes"] + 1)
        if len(content) != wheel["size_bytes"] or digest(content) != wheel["sha256"]:
            raise ValueError("ARM64 wheel differs from reviewed bytes")
        with destination.open("xb") as output:
            output.write(content)
    if (not destination.is_file() or destination.stat().st_size != wheel["size_bytes"]
            or digest(destination.read_bytes()) != wheel["sha256"]):
        raise ValueError("cached ARM64 wheel differs from reviewed bytes")
    return destination


def extract_wheel(wheel_path, vendor):
    seen = set()
    with zipfile.ZipFile(wheel_path) as archive:
        for item in archive.infolist():
            parts = item.filename.rstrip("/").split("/")
            if (not parts or any(part in ("", ".", "..") for part in parts)
                    or item.filename.startswith("/") or "\\" in item.filename
                    or item.flag_bits & 1 or item.filename in seen):
                raise ValueError("ARM64 wheel contains an unsafe member")
            seen.add(item.filename)
            kind = stat.S_IFMT(item.external_attr >> 16)
            if kind not in ((0, stat.S_IFDIR) if item.is_dir()
                            else (0, stat.S_IFREG)):
                raise ValueError("ARM64 wheel contains a special file")
            destination = vendor.joinpath(*parts)
            if item.is_dir():
                destination.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with archive.open(item) as source, destination.open("xb") as output:
                    while block := source.read(1024 * 1024):
                        output.write(block)


def importer():
    spec = importlib.util.spec_from_file_location("phala_snapshot_import", IMPORTER)
    if spec is None or spec.loader is None:
        raise ValueError("reviewed snapshot importer is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True,
                        help="absolute local workspace directory for public data")
    arguments = parser.parse_args()
    if os.uname().machine != "aarch64" or sys.version_info[:2] != (3, 13):
        raise ValueError("local import requires native ARM64 Linux with CPython 3.13")
    value = load_lock()
    work = workspace_dir(arguments.work_dir)
    state = work / "state"
    if state.is_symlink():
        raise ValueError("public state path is a symlink")
    state.mkdir(mode=0o700, exist_ok=True)
    if not state.is_dir() or state.resolve(strict=True) != state:
        raise ValueError("public state path is not a regular directory")
    snapshot = importer()
    selected = snapshot._lock(SNAPSHOT_LOCK, value["source_snapshot_lock_sha256"])
    if ((selected["archive_sha256"], selected["archive_size_bytes"])
            != (value["archive_sha256"], value["archive_size_bytes"])):
        raise ValueError("local import differs from selected public snapshot")
    if (state / "state").exists() or (state / "state").is_symlink():
        snapshot.ensure_snapshot(lock_path=SNAPSHOT_LOCK, state=state)
    else:
        available = os.statvfs(state)
        free_bytes = available.f_bavail * available.f_frsize
        floor = value["archive_size_bytes"] + value["extracted_regular_file_bytes"]
        if free_bytes < floor:
            raise ValueError("workspace is below measured first-boot import floor")
        official_wheel_metadata(value["wheel"])
        require_no_known_advisories(value["wheel"])
        wheel_path = verified_wheel(work, value["wheel"])
        with tempfile.TemporaryDirectory(prefix=".zrpc-arm64-vendor-", dir=work) as temporary:
            vendor = Path(temporary)
            extract_wheel(wheel_path, vendor)
            sys.path.insert(0, str(vendor))
            import zstandard
            if (zstandard.__version__ != value["wheel"]["version"]
                    or not Path(zstandard.__file__).resolve().is_relative_to(vendor)):
                raise ValueError("ARM64 wheel module identity differs")
            snapshot.ensure_snapshot(lock_path=SNAPSHOT_LOCK, state=state)
    print(json.dumps({"mode": "local_unsigned_public_testnet_import",
                      "snapshot_lock_sha256": value["source_snapshot_lock_sha256"],
                      "archive_sha256": value["archive_sha256"],
                      "private_mode_approved": False,
                      "cloud_deployment_approved": False}, sort_keys=True))


if __name__ == "__main__":
    main()
