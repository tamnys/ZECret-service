"""Import one pinned, explicitly unsigned public Testnet snapshot before Zebra starts.

The snapshot is public chain data. Its publisher's checksum is not an
independent signature and this module does not approve private RPC.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile
import urllib.request


LOCK = Path("/opt/zrpc/snapshot.lock.json")
STATE = Path("/var/lib/zebra")
LOCK_SHA256 = "be9d8781d86b9dff803f18d5caf0fc56ec5b3457bca0731fc444f8a4c62960fe"
ARCHIVE = ".zrpc-snapshot.tar.zst"
STAGING = ".zrpc-snapshot-staging"
MARKER = ".zrpc-snapshot-import.json"
CHUNK = 1024 * 1024


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate snapshot lock field")
        value[key] = item
    return value


def _lock(path, expected_digest):
    if path.is_symlink() or not path.is_file():
        raise ValueError("snapshot lock must be a regular image file")
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != expected_digest:
        raise ValueError("snapshot lock differs from reviewed decision")
    value = json.loads(content, object_pairs_hook=_unique_object)
    if (not isinstance(value, dict)
            or value.get("status") != "operator_selected_unsigned_public_preview_only"
            or value.get("network") != "testnet"
            or value.get("manifest_signed") is not False
            or value.get("private_mode_approved") is not False
            or value.get("target_cache_dir") != str(STATE)
            or value.get("archive_extraction_path") != "state/v28/testnet"
            or value.get("database_format_major_version") != 28
            or value.get("target_database_format_major_version") != 29
            or value.get("target_zebrad_version") != "7.0.0-rc.0"
            or not isinstance(value.get("decompressor"), dict)
            or value.get("decompressor", {}).get("package") != "zstandard"
            or value.get("decompressor", {}).get("version") != "0.25.0"
            or value.get("decompressor", {}).get("wheel_sha256") !=
            "8e735494da3db08694d26480f1493ad2cf86e99bdd53e8e9771b2752a5c0246a"
            or type(value.get("archive_size_bytes")) is not int
            or value["archive_size_bytes"] <= 0
            or not isinstance(value.get("archive_sha256"), str)
            or len(value["archive_sha256"]) != 64
            or any(character not in "0123456789abcdef"
                   for character in value["archive_sha256"])
            or not isinstance(value.get("archive_url"), str)
            or not value["archive_url"].startswith("https://snapshots.zfnd.org/testnet/")):
        raise ValueError("snapshot lock is not the selected public Testnet archive")
    return value


def _download(value, destination, opener):
    request = urllib.request.Request(value["archive_url"], headers={
        "User-Agent": "zrpc-public-testnet-snapshot/1", "Cache-Control": "no-cache"})
    expected_size = value["archive_size_bytes"]
    digest = hashlib.sha256()
    with opener(request) as response:
        if response.status != 200 or response.geturl() != value["archive_url"]:
            raise ValueError("snapshot archive URL or HTTP status changed")
        content_length = response.headers.get("Content-Length")
        if content_length is not None and content_length != str(expected_size):
            raise ValueError("snapshot archive HTTP length differs")
        with destination.open("xb") as output:
            os.chmod(destination, 0o600)
            remaining = expected_size
            while remaining:
                block = response.read(min(CHUNK, remaining))
                if not block:
                    raise ValueError("snapshot archive ended early")
                output.write(block)
                digest.update(block)
                remaining -= len(block)
            if response.read(1):
                raise ValueError("snapshot archive exceeded pinned size")
    if digest.hexdigest() != value["archive_sha256"]:
        raise ValueError("snapshot archive differs from selected checksum")


def _member_parts(member):
    name = member.name
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise ValueError("snapshot has unsafe member name")
    parts = name.rstrip("/").split("/")
    if parts and parts[0] == ".":
        parts = parts[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ValueError("snapshot has unsafe member path")
    prefix = ("state", "v28", "testnet")
    if tuple(parts[:min(len(parts), 3)]) != prefix[:min(len(parts), 3)]:
        raise ValueError("snapshot member is outside Testnet state")
    if not member.isdir() and len(parts) <= 3:
        raise ValueError("snapshot state root must be a directory")
    if not (member.isdir() or member.isfile()):
        raise ValueError("snapshot contains link or special file")
    return parts


def _extract(source, staging, decompressor):
    regular_files = 0
    seen = set()
    with source.open("rb") as archive:
        with decompressor(archive) as decoded:
            with tarfile.open(fileobj=decoded, mode="r|") as package:
                for member in package:
                    if member.name in (".", "./") and member.isdir():
                        continue
                    parts = _member_parts(member)
                    relative = "/".join(parts)
                    if relative in seen:
                        raise ValueError("snapshot has duplicate member path")
                    seen.add(relative)
                    destination = staging.joinpath(*parts)
                    if member.isdir():
                        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                        destination.chmod(0o700)
                        continue
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    stream = package.extractfile(member)
                    if stream is None:
                        raise ValueError("snapshot file body is missing")
                    with stream, destination.open("xb") as output:
                        remaining = member.size
                        while remaining:
                            block = stream.read(min(CHUNK, remaining))
                            if not block:
                                raise ValueError("snapshot file ended early")
                            output.write(block)
                            remaining -= len(block)
                    destination.chmod(0o600)
                    regular_files += 1
            while decoded.read(CHUNK):
                pass
    if regular_files == 0 or not (staging / "state/v28/testnet").is_dir():
        raise ValueError("snapshot has no Testnet database files")


def _zstd_reader(source):
    import zstandard  # Pinned CPython 3.13 Linux x86_64 wheel in the image.

    if zstandard.__version__ != "0.25.0":
        raise ValueError("snapshot decompressor differs from pinned version")
    return zstandard.ZstdDecompressor().stream_reader(source)


def _clear_incomplete_import(archive, staging):
    # These exact paths are generated cache files, never published Zebra state.
    if archive.is_symlink():
        raise ValueError("snapshot archive path is a symlink")
    if archive.exists():
        if not archive.is_file():
            raise ValueError("snapshot archive path is not a regular file")
        archive.unlink()
    if staging.is_symlink():
        raise ValueError("snapshot staging path is a symlink")
    if staging.exists():
        if not staging.is_dir():
            raise ValueError("snapshot staging path is not a directory")
        shutil.rmtree(staging)


def ensure_snapshot(lock_path=LOCK, state=STATE, expected_lock_sha256=LOCK_SHA256,
                    opener=urllib.request.urlopen, decompressor=_zstd_reader):
    """Make the selected snapshot available, or fail without starting Zebra."""
    value = _lock(lock_path, expected_lock_sha256)
    if state.is_symlink() or not state.is_dir():
        raise ValueError("snapshot cache is not a regular directory")
    published = state / "state"
    marker = published / MARKER
    archive = state / ARCHIVE
    staging = state / STAGING
    marker_bytes = json.dumps({
        "archive_sha256": value["archive_sha256"],
        "snapshot_lock_sha256": expected_lock_sha256,
    }, sort_keys=True, separators=(",", ":")).encode()
    if published.exists() or published.is_symlink():
        if (published.is_symlink() or not published.is_dir()
                or marker.is_symlink() or not marker.is_file()
                or marker.read_bytes() != marker_bytes):
            raise ValueError("snapshot state or import marker is inconsistent")
        _clear_incomplete_import(archive, staging)
        return
    _clear_incomplete_import(archive, staging)
    _download(value, archive, opener)
    staging.mkdir(mode=0o700)
    _extract(archive, staging, decompressor)
    with (staging / "state" / MARKER).open("xb") as output:
        os.chmod(staging / "state" / MARKER, 0o600)
        output.write(marker_bytes)
    (staging / "state").rename(published)
    staging.rmdir()
    archive.unlink()
