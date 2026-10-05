#!/usr/bin/env python3
"""Check the reviewed dstack Git source before a future native Cargo fetch.

The exact commit is in Cargo.lock. A historical upstream GitHub push-run record,
not its forgeable commit timestamp or mutable release tag, establishes that the
object existed before the workspace's seven-day release hold. This checks source
metadata only: it does not fetch Git objects or crates, run Cargo, or approve a
guest image or private mode.
"""

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sys
import tomllib
import urllib.error
import urllib.request


REPOSITORY = "Dstack-TEE/dstack"
REPOSITORY_ID = 856700396
COMMIT = "282eeb27d22d8f091ad0fa5a90e638f85cf68751"
TREE = "8d75e90384509c4c13775287da0490e7b35406bb"
RUN_ID = 24703241927
RUN_CREATED = "2026-04-21T03:58:44Z"
GIT_URL = "https://github.com/" + REPOSITORY
LOCK_SOURCE = f"git+{GIT_URL}?rev={COMMIT}#{COMMIT}"
PACKAGES = {"cc-eventlog": "0.5.9", "dstack-sdk-types": "0.1.2"}
HOLD = dt.timedelta(days=7)
API = "https://api.github.com/repos/" + REPOSITORY + "/"


class Refusal(Exception):
    pass


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refusal("duplicate GitHub API JSON key")
        result[key] = value
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def github_json(path):
    if path not in (f"git/commits/{COMMIT}", f"actions/runs/{RUN_ID}"):
        raise Refusal("unreviewed GitHub API path")
    headers = {"Accept": "application/vnd.github+json", "Cache-Control": "no-cache, no-store, max-age=0",
               "Pragma": "no-cache", "Accept-Encoding": "identity"}
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        API + path,
        headers=headers,
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request) as response:
            if response.status != 200 or response.url != request.full_url:
                raise Refusal("unexpected GitHub API response")
            return json.loads(response.read().decode("utf-8"), object_pairs_hook=unique_json_object)
    except (urllib.error.URLError, UnicodeError, json.JSONDecodeError, OSError) as error:
        raise Refusal(f"GitHub API record unavailable: {type(error).__name__}") from error


def check_local_inputs(root):
    lock_path = root / "Cargo.lock"
    manifest_path = root / "Cargo.toml"
    if any(not path.is_file() or path.is_symlink() for path in (lock_path, manifest_path)):
        raise Refusal("Cargo inputs must be regular files")
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    manifest = tomllib.loads(manifest_path.read_text())
    if lock.get("version") != 4 or not isinstance(lock.get("package"), list):
        raise Refusal("unreviewed Cargo.lock format")
    selected = {}
    for package in lock["package"]:
        if not isinstance(package, dict):
            raise Refusal("malformed locked package")
        source = package.get("source")
        if not isinstance(source, str) or not source.startswith("git+"):
            continue
        name = package.get("name")
        if not isinstance(name, str) or name not in PACKAGES or name in selected:
            raise Refusal("unreviewed or duplicate Git package")
        if source != LOCK_SOURCE or package.get("version") != PACKAGES[name]:
            raise Refusal("locked Git package differs from reviewed source")
        selected[name] = package["version"]
    if selected != PACKAGES:
        raise Refusal("reviewed Git package missing from Cargo.lock")
    workspace = manifest.get("workspace")
    if not isinstance(workspace, dict) or not isinstance(workspace.get("dependencies"), dict):
        raise Refusal("workspace dependencies are unavailable")
    dependencies = workspace["dependencies"]
    for name, version in PACKAGES.items():
        if dependencies.get(name) != {"git": GIT_URL, "rev": COMMIT, "version": "=" + version}:
            raise Refusal("workspace Git dependency differs from reviewed source")
    return hashlib.sha256(lock_bytes).hexdigest()


def checked_publication_time(value):
    if value != RUN_CREATED:
        raise Refusal("upstream run publication time differs from reviewed record")
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def check_upstream(commit, run, now):
    if (not isinstance(commit, dict) or commit.get("sha") != COMMIT
            or not isinstance(commit.get("tree"), dict)
            or commit["tree"].get("sha") != TREE):
        raise Refusal("upstream Git commit or reviewed tree differs")
    if (not isinstance(run, dict) or run.get("id") != RUN_ID
            or run.get("head_sha") != COMMIT or run.get("event") != "push"
            or run.get("conclusion") != "success"
            or not isinstance(run.get("repository"), dict)
            or run["repository"].get("id") != REPOSITORY_ID
            or not isinstance(run.get("head_repository"), dict)
            or run["head_repository"].get("id") != REPOSITORY_ID):
        raise Refusal("upstream push-run provenance differs")
    published = checked_publication_time(run.get("created_at"))
    if not isinstance(now, dt.datetime) or now.tzinfo is None or now < published + HOLD:
        raise Refusal("reviewed Git source has not cleared the seven-day hold")


def preflight(root, fetch=github_json, now=None):
    lock_sha256 = check_local_inputs(root)
    commit = fetch(f"git/commits/{COMMIT}")
    run = fetch(f"actions/runs/{RUN_ID}")
    now = now or dt.datetime.now(dt.timezone.utc)
    check_upstream(commit, run, now)
    return {
        "cargo_lock_sha256": lock_sha256,
        "git_packages_checked": sorted(PACKAGES),
        "source_commit": COMMIT,
        "source_tree": TREE,
        "upstream_push_run": RUN_ID,
        "upstream_run_created_at_utc": RUN_CREATED,
        "checked_at_utc": now.astimezone(dt.timezone.utc).isoformat(),
        "git_source_metadata_preflight_passed": True,
        "upstream_commit_signature_verified": False,
        "git_object_fetched_or_checked_locally": False,
        "registry_packages_checked": False,
        "cargo_fetch_executed": False,
        "cargo_build_executed": False,
        "guest_image_built": False,
        "private_mode_approved": False,
    }


def main():
    try:
        result = preflight(Path(__file__).resolve().parents[1])
    except (Refusal, OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError) as error:
        print(json.dumps({"git_source_metadata_preflight_passed": False, "reason": str(error),
                          "cargo_fetch_executed": False, "cargo_build_executed": False,
                          "guest_image_built": False, "private_mode_approved": False}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
