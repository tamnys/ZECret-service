#!/usr/bin/env python3
"""Fail closed on the locked crates.io registry graph before any Cargo fetch.

This preflight makes fresh HTTPS requests to the official sparse index. It does
not download crate archives, validate Git sources, run Cargo, or approve a build.
The seven-day hold comes from the workspace supply-chain policy; Cargo 1.94.1
does not enforce it for an existing lockfile.
"""

import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
import urllib.error
import urllib.request


LOCK_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
INDEX = "https://index.crates.io/"
HOLD = dt.timedelta(days=7)
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]*\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PUBTIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
NU7_EXCEPTION_SCOPE = "nu7-testnet-wallet-evaluation-only"
NU7_EXCEPTION_PATH = Path(__file__).with_name("nu7-registry-age-exception.json")
NU7_EXCEPTION_SHA256 = "e188e488b2c236c1e04dc377ec271f012ee0a840fecc9a8c95adddb1b1b84731"


class Refusal(Exception):
    pass


def locked_packages(path):
    if not path.is_file() or path.is_symlink():
        raise Refusal("Cargo.lock must be a regular file")
    raw = path.read_bytes()
    lock = tomllib.loads(raw.decode("utf-8"))
    if lock.get("version") != 4 or not isinstance(lock.get("package"), list):
        raise Refusal("unreviewed Cargo.lock format")
    packages = {}
    local_packages = 0
    git_sources = 0
    for package in lock["package"]:
        if not isinstance(package, dict):
            raise Refusal("malformed lock package")
        if (not isinstance(package.get("name"), str) or not package["name"]
                or not isinstance(package.get("version"), str) or not package["version"]):
            raise Refusal("missing Cargo.lock package identity")
        source = package.get("source")
        if source is None:
            local_packages += 1  # Workspace/path package; this preflight does not audit it.
            continue
        if source != LOCK_SOURCE:
            if isinstance(source, str) and source.startswith("git+https://") and re.search(r"#[0-9a-f]{40}\Z", source):
                git_sources += 1  # Pinned Git source needs its separate review.
                continue
            raise Refusal("unknown or unpinned Cargo source")
        name, version, checksum = (package.get(key) for key in ("name", "version", "checksum"))
        if (not isinstance(name, str) or not NAME.fullmatch(name)
                or not isinstance(version, str) or not version
                or not isinstance(checksum, str) or not SHA256.fullmatch(checksum)):
            raise Refusal("invalid registry identity or checksum in Cargo.lock")
        key = (name, version)
        if key in packages:
            raise Refusal("duplicate registry package in Cargo.lock")
        packages[key] = checksum
    if not packages:
        raise Refusal("Cargo.lock has no registry packages")
    return packages, local_packages, git_sources, hashlib.sha256(raw).hexdigest()


def index_path(name):
    name = name.lower()
    if len(name) == 1:
        return "1/" + name
    if len(name) == 2:
        return "2/" + name
    if len(name) == 3:
        return "3/" + name[0] + "/" + name
    return name[:2] + "/" + name[2:4] + "/" + name


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def fetch_index(name):
    # No proxy, redirect, conditional request, or local sparse-index cache. A
    # server-side stale response can still exist; this is not a transparency log.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(
        INDEX + index_path(name),
        headers={"Cache-Control": "no-cache, no-store, max-age=0", "Pragma": "no-cache", "Accept-Encoding": "identity"},
    )
    try:
        with opener.open(request) as response:
            if response.status != 200 or response.url != request.full_url:
                raise Refusal("unexpected crates.io index response")
            return response.read().decode("utf-8")
    except (urllib.error.URLError, UnicodeError, OSError) as error:
        raise Refusal(f"crates.io index unavailable for {name}: {type(error).__name__}") from error


def publish_time(value):
    if not isinstance(value, str) or not PUBTIME.fullmatch(value):
        raise Refusal("missing or malformed sparse-index pubtime")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError as error:
        raise Refusal("invalid sparse-index pubtime") from error


def unique_json_object(pairs):
    entry = {}
    for key, value in pairs:
        if key in entry:
            raise Refusal("duplicate sparse-index JSON key")
        entry[key] = value
    return entry


def load_exception(path, expected_sha256, lock_sha256, packages):
    if not path.is_file() or path.is_symlink():
        raise Refusal("NU7 exception must be a regular file")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise Refusal("NU7 exception manifest digest differs from review")
    try:
        manifest = json.loads(raw, object_pairs_hook=unique_json_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Refusal("malformed NU7 exception manifest") from error
    if (not isinstance(manifest, dict)
            or set(manifest) != {"schema_version", "scope", "cargo_lock_sha256", "packages"}
            or manifest["schema_version"] != 1
            or manifest["scope"] != NU7_EXCEPTION_SCOPE
            or manifest["cargo_lock_sha256"] != lock_sha256
            or not isinstance(manifest["packages"], list)):
        raise Refusal("NU7 exception is not bound to this exact lockfile")
    approved = set()
    for item in manifest["packages"]:
        if not isinstance(item, dict) or set(item) != {"name", "version", "checksum"}:
            raise Refusal("malformed NU7 exception package")
        key = (item["name"], item["version"])
        if (not all(isinstance(value, str) for value in key)
                or not NAME.fullmatch(key[0]) or not key[1]
                or key in approved or packages.get(key) != item["checksum"]):
            raise Refusal("NU7 exception package differs from locked registry input")
        approved.add(key)
    if not approved:
        raise Refusal("empty NU7 exception package set")
    return approved


def check_index(name, versions, response, now):
    found = {}
    for line in response.splitlines():
        try:
            entry = json.loads(line, object_pairs_hook=unique_json_object)
        except (json.JSONDecodeError, TypeError) as error:
            raise Refusal(f"malformed sparse-index JSON for {name}") from error
        if not isinstance(entry, dict):
            raise Refusal(f"malformed sparse-index entry for {name}")
        version = entry.get("vers")
        if not isinstance(version, str) or not version:
            raise Refusal(f"malformed sparse-index version for {name}")
        if version not in versions:
            continue
        if version in found:
            raise Refusal(f"duplicate sparse-index version for {name}")
        if entry.get("name") != name:
            raise Refusal(f"sparse-index identity mismatch for {name}")
        checksum = entry.get("cksum")
        if not isinstance(checksum, str) or checksum != versions[version]:
            raise Refusal(f"sparse-index checksum mismatch for {name} {version}")
        if entry.get("yanked") is not False:
            raise Refusal(f"sparse-index version is yanked or has unknown status: {name} {version}")
        published = publish_time(entry.get("pubtime"))
        found[version] = published
    if set(found) != set(versions):
        raise Refusal(f"locked version missing from sparse index for {name}")
    return [(name, version, published + HOLD) for version, published in found.items()
            if now < published + HOLD]


def preflight(lock_path, fetch=fetch_index, now=None, exception_path=None,
              exception_sha256=None):
    packages, local_packages, git_sources, lock_sha256 = locked_packages(lock_path)
    if (exception_path is None) != (exception_sha256 is None):
        raise Refusal("NU7 exception path and digest must be supplied together")
    approved = (load_exception(exception_path, exception_sha256, lock_sha256, packages)
                if exception_path is not None else set())
    grouped = {}
    for (name, version), checksum in packages.items():
        grouped.setdefault(name, {})[version] = checksum
    # Take the clock after the live requests, so expiry during this pass can
    # become eligible at the actual decision time.
    responses = {name: fetch(name) for name in sorted(grouped)}
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise Refusal("UTC-aware clock required")
    young = []
    for name in sorted(grouped):
        young.extend(check_index(name, grouped[name], responses[name], now))
    rejected = [(name, version) for name, version, _ in young
                if (name, version) not in approved]
    accepted = [(name, version) for name, version, _ in young
                if (name, version) in approved]
    return {
        "cargo_lock_sha256": lock_sha256,
        "registry_package_count": len(packages),
        "local_packages_not_audited": local_packages,
        "git_packages_not_audited": git_sources,
        "checked_at_utc": now.astimezone(dt.timezone.utc).isoformat(),
        "release_hold_days": HOLD.days,
        "younger_than_hold": [
            {"name": name, "version": version, "eligible_after_utc": expiry.isoformat()}
            for name, version, expiry in sorted(young)
        ],
        "registry_preflight_passed": not rejected,
        "hold_exception_scope": NU7_EXCEPTION_SCOPE if exception_path else None,
        "hold_exception_manifest_sha256": exception_sha256,
        "hold_exception_applied": [
            {"name": name, "version": version} for name, version in sorted(accepted)
        ],
        "cargo_fetch_executed": False,
        "cargo_build_executed": False,
        "dependency_closure_verified": False,
        "approved_release": False,
        "private_mode_approved": False,
    }


def main():
    try:
        arguments = sys.argv[1:]
        if arguments not in ([], ["--payment-helper"], ["--nu7-testnet-wallet-evaluation"]):
            raise Refusal("only workspace, payment helper, or exact NU7 evaluation may be checked")
        relative = ("tools/payment-crypto/Cargo.lock" if arguments == ["--payment-helper"]
                    else "Cargo.lock")
        lock = Path(__file__).resolve().parents[1] / relative
        nu7 = arguments == ["--nu7-testnet-wallet-evaluation"]
        result = preflight(lock, exception_path=NU7_EXCEPTION_PATH if nu7 else None,
                           exception_sha256=NU7_EXCEPTION_SHA256 if nu7 else None)
    except (Refusal, OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError) as error:
        print(json.dumps({"registry_preflight_passed": False, "reason": str(error),
                          "cargo_fetch_executed": False, "cargo_build_executed": False,
                          "approved_release": False, "private_mode_approved": False}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["registry_preflight_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
