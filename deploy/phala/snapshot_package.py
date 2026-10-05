"""Reviewed, unsigned snapshot inputs for the public Phala preview image.

The published archive and wheel hashes pin bytes. Neither is a private-mode
approval; the snapshot publisher's own checksum is not an independent signature.
"""

import hashlib
import io
import json
from pathlib import Path
import stat
import zipfile


HERE = Path(__file__).resolve().parent
LOCK_SHA256 = "be9d8781d86b9dff803f18d5caf0fc56ec5b3457bca0731fc444f8a4c62960fe"
CONTEXT_FILES = ("snapshot_import.py", "snapshot.lock.json",
                 "vendor/zstandard.whl")


def _regular_bytes(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("regular non-symlink snapshot input required")
    return path.read_bytes()


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate snapshot lock field")
        value[key] = item
    return value


def reviewed_lock():
    content = _regular_bytes(HERE / "snapshot.lock.json")
    if hashlib.sha256(content).hexdigest() != LOCK_SHA256:
        raise ValueError("snapshot decision differs from reviewed lock")
    value = json.loads(content, object_pairs_hook=_unique_object)
    wheel = value.get("decompressor", {})
    if (value.get("status") != "operator_selected_unsigned_public_preview_only"
            or value.get("network") != "testnet"
            or value.get("manifest_signed") is not False
            or value.get("private_mode_approved") is not False
            or value.get("target_cache_dir") != "/var/lib/zebra"
            or value.get("archive_extraction_path") != "state/v28/testnet"
            or value.get("database_format_major_version") != 28
            or value.get("target_database_format_major_version") != 29
            or value.get("target_zebrad_version") != "7.0.0-rc.0"
            or value.get("target_zebrad_source_commit") !=
            "6d1e414d6f55e4180d0e47baaa934bf97d5b4fec"
            or value.get("target_database_format_source_sha256") !=
            "33d76f958cf88ddcdaae22675f2d8c9929542ea3ef9ae77d78f361c273abb7c8"
            or wheel.get("package") != "zstandard"
            or wheel.get("version") != "0.25.0"
            or wheel.get("wheel_filename") !=
            "zstandard-0.25.0-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl"
            or wheel.get("wheel_size_bytes") != 5547173
            or wheel.get("wheel_sha256") !=
            "8e735494da3db08694d26480f1493ad2cf86e99bdd53e8e9771b2752a5c0246a"):
        raise ValueError("snapshot lock is not the selected public preview input")
    return value, content


def _checked_wheel(path, wheel):
    content = _regular_bytes(path)
    if (len(content) != wheel["wheel_size_bytes"]
            or hashlib.sha256(content).hexdigest() != wheel["wheel_sha256"]):
        raise ValueError("snapshot decompressor differs from pinned wheel")
    with zipfile.ZipFile(io.BytesIO(content)) as package:
        names = set()
        for member in package.infolist():
            name = member.filename
            parts = name.rstrip("/").split("/")
            mode = stat.S_IFMT(member.external_attr >> 16)
            if (not name or name.startswith("/") or "\\" in name
                    or any(part in ("", ".", "..") for part in parts)
                    or mode not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or name in names):
                raise ValueError("snapshot decompressor wheel has unsafe members")
            names.add(name)
        if ("zstandard/__init__.py" not in names
                or "zstandard/backend_c.cpython-313-x86_64-linux-gnu.so" not in names
                or "zstandard-0.25.0.dist-info/WHEEL" not in names
                or package.testzip() is not None):
            raise ValueError("snapshot decompressor wheel is incomplete")
    return content


def reviewed_context_inputs(wheel_path):
    lock, lock_bytes = reviewed_lock()
    importer = _regular_bytes(HERE / "image/snapshot_import.py")
    if f'LOCK_SHA256 = "{LOCK_SHA256}"'.encode() not in importer:
        raise ValueError("snapshot importer and decision lock disagree")
    return {
        "snapshot_import.py": importer,
        "snapshot.lock.json": lock_bytes,
        "vendor/zstandard.whl": _checked_wheel(wheel_path, lock["decompressor"]),
    }


def check_context(directory):
    directory = Path(directory)
    expected = reviewed_context_inputs(directory / "vendor/zstandard.whl")
    for name, content in expected.items():
        if _regular_bytes(directory / name) != content:
            raise ValueError("snapshot image input differs from reviewed source")
