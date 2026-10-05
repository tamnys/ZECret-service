#!/usr/bin/env python3
"""Explicit Zebra release preflight and local, data-only artifact staging.

Preflight reads only official GitHub release/tag/advisory metadata. Staging
accepts an already-downloaded local archive after the policy hold, or with the
explicit v7.0.0-rc.0 local staging exception, verifies it with a separately pinned
GitHub CLI, and emits an unapproved diagnostic input.
Neither command downloads release assets, builds an image, or approves privacy.
"""

import argparse
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "deploy/gcp/zebra-release.lock.json"
BUNDLE_PATH = ROOT / "records/zebra-v700rc0-attestation-bundle.json"
API = "https://api.github.com/repos/ZcashFoundation/zebra"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA1 = re.compile(r"[0-9a-f]{40}\Z")
TAR_MEMBERS = {"zebrad", "LICENSE-APACHE", "LICENSE-MIT", "README.md"}
LOCAL_HOLD_EXCEPTION = {
    "scope": "local-stage-and-image-context-only",
    "release_id": 401443178,
    "tag": "v7.0.0-rc.0",
    "asset_id": 604416112,
    "asset_sha256": "7486dcd91c18d9b8778c632a0cd8e5639d6313ae4d88bc8fd09b1bb7eb12c1f2",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        raise ValueError("GitHub metadata endpoint redirected")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def read_json(data):
    def reject_nonfinite(_value):
        raise ValueError("nonstandard JSON number")

    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=reject_nonfinite)


def utc(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("UTC timestamp required")
    result = datetime.fromisoformat(value[:-1] + "+00:00")
    if result.utcoffset() != timedelta(0):
        raise ValueError("UTC timestamp required")
    return result


def load_lock():
    descriptor, before = regular_file(LOCK_PATH)
    with os.fdopen(descriptor, "rb") as stream:
        lock_bytes = stream.read()
        after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                    after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("reviewed Zebra release lock changed while reading")
    lock = read_json(lock_bytes)
    required = {"schema_version", "status", "repository", "release_id",
                "tag", "tag_object_sha", "source_commit", "published_at",
                "minimum_age_days", "asset", "signer_workflow",
                "attestation_bundle",
                "reviewed_advisory_count", "reviewed_advisory_snapshot_sha256",
                "gh_verifier_source",
                "gh_verifier_executable_sha256", "zebrad_elf_sha256",
                "zebrad_elf_size"}
    if (not isinstance(lock, dict) or set(lock) != required
            or lock["schema_version"] != 1
            or lock["status"] != "reviewed-metadata-only-unapproved"
            or lock["repository"] != "ZcashFoundation/zebra"
            or lock["tag"] != "v7.0.0-rc.0"
            or lock["minimum_age_days"] != 7
            or lock["signer_workflow"] !=
            "ZcashFoundation/zebra/.github/workflows/zfnd-release-binaries.yml"
            or type(lock["release_id"]) is not int or lock["release_id"] <= 0
            or not SHA1.fullmatch(lock["tag_object_sha"])
            or not SHA1.fullmatch(lock["source_commit"])
            or not SHA256.fullmatch(lock["reviewed_advisory_snapshot_sha256"])
            or type(lock["reviewed_advisory_count"]) is not int
            or lock["reviewed_advisory_count"] <= 0):
        raise ValueError("Zebra release lock is incomplete or changed")
    utc(lock["published_at"])
    asset = lock["asset"]
    if (not isinstance(asset, dict)
            or set(asset) != {"id", "name", "size", "sha256", "created_at", "updated_at"}
            or type(asset["id"]) is not int or asset["id"] <= 0
            or asset["name"] != "zebrad-7.0.0-rc.0-x86_64-unknown-linux-gnu.tar.gz"
            or type(asset["size"]) is not int or asset["size"] <= 0
            or not SHA256.fullmatch(asset["sha256"])):
        raise ValueError("reviewed x86_64 asset identity missing")
    utc(asset["created_at"])
    utc(asset["updated_at"])
    bundle = lock["attestation_bundle"]
    if (not isinstance(bundle, dict)
            or set(bundle) != {"source_url", "size", "sha256"}
            or bundle["source_url"] != API + "/attestations/sha256:" + asset["sha256"]
            or type(bundle["size"]) is not int or bundle["size"] <= 0
            or not SHA256.fullmatch(bundle["sha256"])):
        raise ValueError("reviewed Zebra attestation bundle identity missing")
    if lock["gh_verifier_source"] != {
            "repository": "cli/cli", "tag": "v2.100.0",
            "asset_name": "gh_2.100.0_linux_arm64.tar.gz",
            "asset_size": 13783869,
            "asset_sha256": "ea4e7a581a32ccad6cc7923cb1576ac5859ba4b9a16ab22eb8f8a96e78e2e961",
            "archive_member": "gh_2.100.0_linux_arm64/bin/gh"}:
        raise ValueError("maintained attestation verifier source differs")
    for field in ("gh_verifier_executable_sha256", "zebrad_elf_sha256"):
        if lock[field] is not None and (not isinstance(lock[field], str)
                                        or not SHA256.fullmatch(lock[field])):
            raise ValueError("reviewed verifier or ELF digest malformed")
    if lock["zebrad_elf_size"] is not None and (type(lock["zebrad_elf_size"]) is not int
                                                or lock["zebrad_elf_size"] <= 0):
        raise ValueError("reviewed ELF size malformed")
    return lock, hashlib.sha256(lock_bytes).hexdigest()


def fetch_json(url):
    request = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json",
                      "User-Agent": "zrpc-zebra-artifact-preflight/1",
                      "Cache-Control": "no-cache"})
    # Reject 30x before urllib can follow it and read an asset body during the
    # release hold. A final-URL check alone would be too late.
    with urllib.request.build_opener(NoRedirect()).open(request) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("official GitHub metadata endpoint changed")
        if "rel=\"next\"" in response.headers.get("Link", ""):
            raise ValueError("published advisory list is incomplete")
        date = parsedate_to_datetime(response.headers["Date"])
        if date.tzinfo is None:
            raise ValueError("GitHub response lacks server UTC time")
        return read_json(response.read()), date.astimezone(timezone.utc)


def advisory_snapshot(advisories):
    if not isinstance(advisories, list) or not advisories:
        raise ValueError("published advisories missing")
    records = []
    for advisory in advisories:
        if not isinstance(advisory, dict) or not isinstance(advisory.get("vulnerabilities"), list):
            raise ValueError("published advisory malformed")
        vulnerabilities = []
        for vulnerability in advisory["vulnerabilities"]:
            package = vulnerability.get("package") if isinstance(vulnerability, dict) else None
            if (not isinstance(package, dict)
                    or not isinstance(vulnerability.get("vulnerable_version_range"), str)
                    or not isinstance(vulnerability.get("patched_versions"), str)):
                raise ValueError("published vulnerability malformed")
            vulnerabilities.append({
                "ecosystem": package.get("ecosystem"), "package": package.get("name"),
                "range": vulnerability.get("vulnerable_version_range"),
                "patched_versions": vulnerability["patched_versions"],
            })
        if (not isinstance(advisory.get("ghsa_id"), str)
                or not isinstance(advisory.get("updated_at"), str)
                or not isinstance(advisory.get("published_at"), str)):
            raise ValueError("published advisory identity malformed")
        records.append({"ghsa_id": advisory["ghsa_id"],
                        "updated_at": advisory["updated_at"],
                        "published_at": advisory["published_at"],
                        "withdrawn_at": advisory.get("withdrawn_at"),
                        "vulnerabilities": sorted(vulnerabilities,
                                                  key=lambda item: json.dumps(item, sort_keys=True))})
    ids = [record["ghsa_id"] for record in records]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate published advisory")
    payload = json.dumps(sorted(records, key=lambda item: item["ghsa_id"]),
                         sort_keys=True, separators=(",", ":")).encode()
    return len(records), hashlib.sha256(payload).hexdigest()


def check_metadata(lock, release, tag_ref, tag_object, advisories, now):
    asset = lock["asset"]
    if (not isinstance(release, dict)
            or any(release.get(key) != value for key, value in (
                ("id", lock["release_id"]), ("tag_name", lock["tag"]),
                ("target_commitish", lock["source_commit"]),
                ("published_at", lock["published_at"]),
                ("draft", False), ("prerelease", False)))
            or not isinstance(release.get("assets"), list)):
        raise ValueError("upstream release differs from reviewed identity")
    matches = [item for item in release["assets"] if isinstance(item, dict)
               and item.get("name") == asset["name"]]
    if len(matches) != 1 or any(matches[0].get(key) != value for key, value in (
            ("id", asset["id"]), ("size", asset["size"]),
            ("digest", "sha256:" + asset["sha256"]),
            ("created_at", asset["created_at"]),
            ("updated_at", asset["updated_at"]), ("state", "uploaded"))):
        raise ValueError("upstream x86_64 asset changed or disappeared")
    if (not isinstance(tag_ref, dict) or tag_ref.get("ref") != "refs/tags/" + lock["tag"]
            or not isinstance(tag_ref.get("object"), dict)
            or tag_ref["object"].get("type") != "tag"
            or tag_ref["object"].get("sha") != lock["tag_object_sha"]
            or not isinstance(tag_object, dict) or tag_object.get("tag") != lock["tag"]
            or tag_object.get("sha") != lock["tag_object_sha"]
            or not isinstance(tag_object.get("object"), dict)
            or tag_object["object"].get("type") != "commit"
            or tag_object["object"].get("sha") != lock["source_commit"]):
        raise ValueError("upstream tag changed from reviewed source")
    count, snapshot = advisory_snapshot(advisories)
    if (count != lock["reviewed_advisory_count"]
            or snapshot != lock["reviewed_advisory_snapshot_sha256"]):
        raise ValueError("upstream advisories changed; new review required")
    eligible_at = utc(asset["created_at"]) + timedelta(days=lock["minimum_age_days"])
    return {"schema_version": 1,
            "status": "age-eligible-metadata-only-unapproved" if now >= eligible_at
            else "held-metadata-only-unapproved",
            "checked_at_utc": now.isoformat().replace("+00:00", "Z"),
            "eligible_at_utc": eligible_at.isoformat().replace("+00:00", "Z"),
            "archive_downloaded_by_tool": False,
            "image_built": False, "private_mode_approved": False}


def live_preflight(lock):
    release, release_time = fetch_json(API + "/releases/tags/" + lock["tag"])
    tag_ref, ref_time = fetch_json(API + "/git/ref/tags/" + lock["tag"])
    tag_object, tag_time = fetch_json(API + "/git/tags/" + lock["tag_object_sha"])
    advisories, advisory_time = fetch_json(API + "/security-advisories?state=published&per_page=100")
    return check_metadata(lock, release, tag_ref, tag_object, advisories,
                          min(release_time, ref_time, tag_time, advisory_time))


def regular_file(path):
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("absolute non-symlink regular file required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        raise ValueError("regular file required")
    return descriptor, info


def sha256_file(path):
    descriptor, before = regular_file(path)
    with os.fdopen(descriptor, "rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                    after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("file changed while hashing")
    return after.st_size, digest


def sealed_verifier_fd(verifier, expected_sha256):
    """Snapshot the reviewed executable into a sealed Linux memfd."""
    if not (hasattr(os, "memfd_create") and hasattr(os, "MFD_ALLOW_SEALING")
            and hasattr(os, "MFD_CLOEXEC")
            and all(hasattr(fcntl, name) for name in (
                "F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE", "F_SEAL_GROW",
                "F_SEAL_SHRINK", "F_SEAL_SEAL"))):
        raise ValueError("Linux sealed executable support unavailable")
    source_fd, before = regular_file(verifier)
    try:
        sealed_fd = os.memfd_create("zrpc-reviewed-gh",
                                    os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    except Exception:
        os.close(source_fd)
        raise
    try:
        digest = hashlib.sha256()
        with os.fdopen(source_fd, "rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(sealed_fd, view)
                    if written <= 0:
                        raise ValueError("attestation verifier could not be snapshotted")
                    view = view[written:]
            after = os.fstat(source.fileno())
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                 after.st_ctime_ns)
                or digest.hexdigest() != expected_sha256):
            raise ValueError("attestation verifier differs from reviewed executable")
        seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                 | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        fcntl.fcntl(sealed_fd, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(sealed_fd, fcntl.F_GET_SEALS) & seals != seals:
            raise ValueError("attestation verifier could not be sealed")
        return sealed_fd
    except Exception:
        os.close(sealed_fd)
        raise


def verify_gh(lock, verifier, archive):
    if lock["gh_verifier_executable_sha256"] is None:
        raise ValueError("pinned maintained attestation verifier is not reviewed")
    if sha256_file(BUNDLE_PATH) != (lock["attestation_bundle"]["size"],
                                    lock["attestation_bundle"]["sha256"]):
        raise ValueError("Zebra attestation bundle differs from reviewed bytes")
    sealed_fd = sealed_verifier_fd(verifier, lock["gh_verifier_executable_sha256"])
    try:
        executable = f"/proc/self/fd/{sealed_fd}"
        command = [executable, "attestation", "verify", str(archive),
                   "--repo", lock["repository"],
                   "--bundle", str(BUNDLE_PATH),
                   "--signer-workflow", lock["signer_workflow"],
                   "--signer-digest", lock["source_commit"],
                   "--source-digest", lock["source_commit"],
                   "--source-ref", "refs/tags/" + lock["tag"],
                   "--deny-self-hosted-runners", "--format", "json"]
        result = subprocess.run(command, executable=executable,
                                pass_fds=(sealed_fd,), capture_output=True,
                                check=False)
    finally:
        os.close(sealed_fd)
    if result.returncode:
        raise ValueError("GitHub attestation verification failed")
    verified = read_json(result.stdout)
    expected_subject = {"name": lock["asset"]["name"],
                        "digest": {"sha256": lock["asset"]["sha256"]}}
    if (not isinstance(verified, list) or not verified
            or any(not isinstance(item, dict)
                   or not isinstance(item.get("verificationResult"), dict)
                   or not isinstance(item["verificationResult"].get("statement"), dict)
                   or item["verificationResult"]["statement"].get("predicateType")
                   != "https://slsa.dev/provenance/v1"
                   or expected_subject not in item["verificationResult"]["statement"].get("subject", [])
                   for item in verified)):
        raise ValueError("verified attestation subject or predicate differs")
    return len(verified)


def extract_zebrad(archive, destination):
    with tarfile.open(archive, "r:gz") as package:
        members = package.getmembers()
        if (len(members) != len(TAR_MEMBERS)
                or {item.name for item in members} != TAR_MEMBERS
                or any(not item.isfile() for item in members)):
            raise ValueError("Zebra release archive has unexpected members")
        member = next(item for item in members if item.name == "zebrad")
        with package.extractfile(member) as source, destination.open("xb") as output:
            if source is None:
                raise ValueError("Zebra executable member missing")
            shutil.copyfileobj(source, output)
    size, digest = sha256_file(destination)
    with destination.open("rb") as binary:
        header = binary.read(64)
    if (size != member.size or header[:6] != b"\x7fELF\x02\x01"
            or header[16:18] not in (b"\x02\x00", b"\x03\x00")
            or header[18:20] != b"\x3e\x00"):
        raise ValueError("archive does not contain an x86_64 executable ELF")
    destination.chmod(0o555)
    return size, digest


def selected_hold_exception(lock, preflight, allow_local_hold_exception):
    if preflight["status"] == "age-eligible-metadata-only-unapproved":
        if allow_local_hold_exception:
            raise ValueError("local Zebra hold exception is unnecessary after eligibility")
        return None
    if (preflight["status"] != "held-metadata-only-unapproved"
            or not allow_local_hold_exception
            or {"scope": "local-stage-and-image-context-only",
                "release_id": lock["release_id"], "tag": lock["tag"],
                "asset_id": lock["asset"]["id"],
                "asset_sha256": lock["asset"]["sha256"]} != LOCAL_HOLD_EXCEPTION
            or lock["minimum_age_days"] != 7
            or utc(preflight["checked_at_utc"]) >= utc(preflight["eligible_at_utc"])):
        raise ValueError("Zebra x86_64 asset remains inside seven-day release hold")
    return LOCAL_HOLD_EXCEPTION.copy()


def stage(lock, lock_sha256, archive, verifier, output,
          allow_local_hold_exception=False):
    preflight = live_preflight(lock)
    exception = selected_hold_exception(lock, preflight, allow_local_hold_exception)
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ValueError("fresh absolute output directory required")
    repository = ROOT.resolve(strict=True)
    if (not output.parent.resolve(strict=True).is_relative_to(repository)
            or not archive.resolve(strict=True).is_relative_to(repository)):
        raise ValueError("artifact inputs and output must remain on the managed workspace volume")
    if lock["zebrad_elf_sha256"] is None or lock["zebrad_elf_size"] is None:
        raise ValueError("reviewed x86_64 ELF identity is not pinned")
    source_size, source_hash = sha256_file(archive)
    if (source_size, source_hash) != (lock["asset"]["size"], lock["asset"]["sha256"]):
        raise ValueError("Zebra archive differs from reviewed release asset")
    temporary = Path(tempfile.mkdtemp(prefix=".zebra-stage-", dir=output.parent))
    try:
        copied = temporary / lock["asset"]["name"]
        shutil.copyfile(archive, copied)
        if sha256_file(copied) != (source_size, source_hash):
            raise ValueError("Zebra archive changed during staging")
        copied.chmod(0o444)
        attestations = verify_gh(lock, verifier, copied)
        binary = temporary / "zebrad"
        size, digest = extract_zebrad(copied, binary)
        if (size, digest) != (lock["zebrad_elf_size"], lock["zebrad_elf_sha256"]):
            raise ValueError("Zebra ELF differs from reviewed identity")
        receipt = {**preflight,
                   "status": "staged-diagnostic-unapproved",
                   "local_hold_exception": exception,
                   "asset_sha256": source_hash,
                   "zebrad_elf_sha256": digest,
                   "zebrad_elf_size": size,
                   "verified_attestation_count": attestations,
                   "gh_verifier_executable_sha256": lock["gh_verifier_executable_sha256"],
                   "release_lock_sha256": lock_sha256}
        (temporary / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        temporary.rename(output)
        return receipt
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("preflight")
    staging = commands.add_parser("stage")
    staging.add_argument("--archive", required=True, type=Path)
    staging.add_argument("--verifier", required=True, type=Path)
    staging.add_argument("--output", required=True, type=Path)
    staging.add_argument("--allow-nu7-local-hold-exception", action="store_true")
    args = parser.parse_args()
    try:
        lock, lock_sha256 = load_lock()
        if args.command == "preflight":
            report = live_preflight(lock)
        else:
            report = stage(lock, lock_sha256, args.archive, args.verifier, args.output,
                           args.allow_nu7_local_hold_exception)
        print(json.dumps(report, indent=2))
        return 0 if report["status"] != "held-metadata-only-unapproved" else 2
    except (OSError, ValueError, TypeError, KeyError, tarfile.TarError) as error:
        print(json.dumps({"status": "blocked", "error": str(error),
                          "image_built": False, "private_mode_approved": False}),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
