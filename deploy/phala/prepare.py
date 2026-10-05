#!/usr/bin/env python3
"""Offline, unapproved packaging inputs for a stock Phala public testnet preview."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
snapshot_spec = importlib.util.spec_from_file_location(
    "phala_snapshot_package", HERE / "snapshot_package.py")
snapshot_package = importlib.util.module_from_spec(snapshot_spec)
snapshot_spec.loader.exec_module(snapshot_package)
STOCK_LOCK = HERE / "stock-candidate.lock.json"
ZEBRA_LOCK = ROOT / "deploy/gcp/zebra-release.lock.json"
REVIEWED_ZEBRA_RECEIPT = ROOT / "records/zebra-v700rc0-local-staging-receipt.json"
STOCK_LOCK_SHA256 = "901015ea91a47e471816475651d9d8095203e314a227eda837b923d934f7cf69"
BASE_IMAGE = ("docker.io/library/python:3.13.15-slim-trixie@sha256:"
              "37134a49d21d2120e4c4d73bb76f8a4ab9aef31f096f7ec2ead48c2feead4332")
# Created annotation in the pinned linux/amd64 OCI manifest.
BASE_IMAGE_CREATED_AT = "2026-09-19T00:58:14Z"
NATIVE_BINARIES_SHA256 = {
    "zrpc-node-wrapper": "85dfd9ea8baa45467e4f29c0173cd22b6a4090cad97c2244714c905e5e188317",
    "zrpc-quote-proxy": "7c4e84de4d3278fbdd47ee81427c642a9bf01d3993b90796dab63f544edc023f",
}
CONTEXT_FILES = ("Dockerfile", "supervisor.py", "zebra.toml", "state/.keep",
                 "zebra-stage-receipt.json",
                 "bin/zebrad", "bin/zrpc-node-wrapper", "bin/zrpc-quote-proxy") + \
                snapshot_package.CONTEXT_FILES
IMAGE_REF = re.compile(r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
LOCAL_HOLD_EXCEPTION = {
    "scope": "local-stage-and-image-context-only",
    "release_id": 401443178,
    "tag": "v7.0.0-rc.0",
    "asset_id": 604416112,
    "asset_sha256": "7486dcd91c18d9b8778c632a0cd8e5639d6313ae4d88bc8fd09b1bb7eb12c1f2",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def parse_json(data):
    def reject_nonfinite(_value):
        raise ValueError("nonfinite JSON")

    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=reject_nonfinite)


def read_json(path):
    return parse_json(regular_bytes(path))


def regular_bytes(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("regular non-symlink input required")
    return path.read_bytes()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def utc(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("UTC timestamp required")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def locks():
    stock_bytes = regular_bytes(STOCK_LOCK)
    zebra_bytes = regular_bytes(ZEBRA_LOCK)
    stock = parse_json(stock_bytes)
    zebra = parse_json(zebra_bytes)
    if (digest(stock_bytes) != STOCK_LOCK_SHA256
            or stock.get("schema_version") != 1
            or stock.get("status") != "observed-stock-candidate-unapproved"
            or stock.get("os_image_sha256") !=
            "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033"
            or stock.get("kms_catalog_id") != "kms_opjg1KBD"
            or stock.get("zebra_release_lock_sha256") != digest(zebra_bytes)
            or not isinstance(stock.get("reviewed_zebra_local_hold_receipt_sha256"), str)
            or not SHA256.fullmatch(stock["reviewed_zebra_local_hold_receipt_sha256"])
            or digest(regular_bytes(REVIEWED_ZEBRA_RECEIPT)) !=
            stock["reviewed_zebra_local_hold_receipt_sha256"]
            or stock.get("private_accepted") is not False
            or stock.get("deployment_enabled") is not False
            or zebra.get("status") != "reviewed-metadata-only-unapproved"
            or zebra.get("tag") != "v7.0.0-rc.0"
            or zebra.get("minimum_age_days") != 7
            or zebra.get("asset", {}).get("sha256") !=
            "7486dcd91c18d9b8778c632a0cd8e5639d6313ae4d88bc8fd09b1bb7eb12c1f2"):
        raise ValueError("stock or Zebra identity differs from reviewed candidate")
    return stock, zebra, digest(zebra_bytes)


def eligibility(zebra, now=None):
    now = now or datetime.now(timezone.utc)
    eligible_at = utc(zebra["asset"]["created_at"]) + timedelta(
        days=zebra["minimum_age_days"])
    return now >= eligible_at, eligible_at


def inside_workspace(path):
    path = Path(path)
    if not path.is_absolute() or not path.resolve().is_relative_to(ROOT):
        raise ValueError("input and output must stay on the workspace volume")
    return path


def fresh_output(path):
    path = inside_workspace(path)
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise ValueError("fresh output directory required")
    return path


def checked_elf(path, expected_sha256, expected_size=None):
    path = inside_workspace(path)
    data = regular_bytes(path)
    if (not SHA256.fullmatch(expected_sha256) or digest(data) != expected_sha256
            or (expected_size is not None and len(data) != expected_size)
            or len(data) < 20 or data[:6] != b"\x7fELF\x02\x01"
            or data[16:18] not in (b"\x02\x00", b"\x03\x00")
            or data[18:20] != b"\x3e\x00"):
        raise ValueError("x86_64 ELF differs from supplied reviewed identity")
    return data


def dockerfile_bytes(base_image):
    template = regular_bytes(HERE / "image/Dockerfile.in").decode("ascii")
    prefix = "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n"
    if not template.startswith(prefix):
        raise ValueError("image recipe changed")
    return ("FROM " + base_image + "\n" + template[len(prefix):]).encode()


def context_files_sha256(directory):
    return {name: digest(regular_bytes(directory / name)) for name in CONTEXT_FILES}


def checked_stage_receipt(stock, zebra, lock_digest, receipt, receipt_sha256,
                          eligible, eligible_at):
    required = {"schema_version", "status", "checked_at_utc", "eligible_at_utc",
                "archive_downloaded_by_tool", "image_built", "private_mode_approved",
                "local_hold_exception", "asset_sha256", "zebrad_elf_sha256",
                "zebrad_elf_size", "verified_attestation_count",
                "gh_verifier_executable_sha256", "release_lock_sha256"}
    if (not isinstance(receipt, dict) or set(receipt) != required
            or receipt["schema_version"] != 1
            or receipt["status"] != "staged-diagnostic-unapproved"
            or receipt["release_lock_sha256"] != lock_digest
            or receipt["asset_sha256"] != zebra["asset"]["sha256"]
            or receipt["zebrad_elf_sha256"] != zebra["zebrad_elf_sha256"]
            or receipt["zebrad_elf_size"] != zebra["zebrad_elf_size"]
            or receipt["gh_verifier_executable_sha256"] !=
            zebra["gh_verifier_executable_sha256"]
            or type(receipt["verified_attestation_count"]) is not int
            or receipt["verified_attestation_count"] < 1
            or receipt["archive_downloaded_by_tool"] is not False
            or receipt["image_built"] is not False
            or receipt["private_mode_approved"] is not False
            or zebra["zebrad_elf_sha256"] is None
            or zebra["zebrad_elf_size"] is None
            or utc(receipt["eligible_at_utc"]) != eligible_at):
        raise ValueError("Zebra staging receipt is missing or unreviewed")
    exception = receipt["local_hold_exception"]
    checked_at = utc(receipt["checked_at_utc"])
    if exception is None:
        if not eligible or checked_at < eligible_at:
            raise ValueError("Zebra stage predates eligibility without reviewed exception")
    elif (exception != LOCAL_HOLD_EXCEPTION
          or zebra["release_id"] != LOCAL_HOLD_EXCEPTION["release_id"]
          or zebra["tag"] != LOCAL_HOLD_EXCEPTION["tag"]
          or zebra["asset"]["id"] != LOCAL_HOLD_EXCEPTION["asset_id"]
          or zebra["asset"]["sha256"] != LOCAL_HOLD_EXCEPTION["asset_sha256"]
          or zebra["minimum_age_days"] != 7
          or receipt_sha256 != stock["reviewed_zebra_local_hold_receipt_sha256"]
          or checked_at >= eligible_at):
        raise ValueError("Zebra local hold exception differs from approved asset")
    return exception


def image_context(args):
    stock, zebra, lock_digest = locks()
    eligible, eligible_at = eligibility(zebra)
    if not eligible and not getattr(args, "allow_nu7_local_hold_exception", False):
        raise ValueError(f"Zebra release hold ends {eligible_at.isoformat()}")
    if (args.base_image != BASE_IMAGE
            or args.base_image_created_at != BASE_IMAGE_CREATED_AT):
        raise ValueError("base image differs from reviewed linux/amd64 manifest")
    if datetime.now(timezone.utc) < utc(BASE_IMAGE_CREATED_AT) + timedelta(days=7):
        raise ValueError("base image is inside the seven-day hold")
    if (args.node_wrapper_sha256 != NATIVE_BINARIES_SHA256["zrpc-node-wrapper"]
            or args.quote_proxy_sha256 != NATIVE_BINARIES_SHA256["zrpc-quote-proxy"]):
        raise ValueError("native binaries differ from reviewed reproducible build")
    stage = inside_workspace(args.zebra_stage)
    receipt_bytes = regular_bytes(stage / "receipt.json")
    receipt = parse_json(receipt_bytes)
    exception = checked_stage_receipt(stock, zebra, lock_digest, receipt,
                                      digest(receipt_bytes), eligible, eligible_at)
    binaries = {
        "zebrad": checked_elf(stage / "zebrad", zebra["zebrad_elf_sha256"],
                              zebra["zebrad_elf_size"]),
        "zrpc-node-wrapper": checked_elf(args.node_wrapper,
                                         args.node_wrapper_sha256),
        "zrpc-quote-proxy": checked_elf(args.quote_proxy,
                                        args.quote_proxy_sha256),
    }
    snapshot_inputs = snapshot_package.reviewed_context_inputs(
        inside_workspace(args.snapshot_wheel))
    snapshot_lock, _ = snapshot_package.reviewed_lock()
    dockerfile = dockerfile_bytes(BASE_IMAGE)
    output = fresh_output(args.output)
    output.mkdir()
    (output / "bin").mkdir()
    (output / "state").mkdir()
    (output / "vendor").mkdir()
    for name, data in binaries.items():
        destination = output / "bin" / name
        destination.write_bytes(data)
        destination.chmod(0o555)
    for name in ("supervisor.py", "zebra.toml"):
        (output / name).write_bytes(regular_bytes(HERE / "image" / name))
    for name, data in snapshot_inputs.items():
        (output / name).write_bytes(data)
    (output / "zebra-stage-receipt.json").write_bytes(receipt_bytes)
    (output / "state/.keep").write_bytes(b"")
    (output / "Dockerfile").write_bytes(dockerfile)
    files_sha256 = context_files_sha256(output)
    result = {
        "schema_version": 1,
        "status": "local-image-context-unapproved",
        "base_image": BASE_IMAGE,
        "base_image_created_at": BASE_IMAGE_CREATED_AT,
        "stock_os_image_sha256": stock["os_image_sha256"],
        "stock_candidate_lock_sha256": STOCK_LOCK_SHA256,
        "zebra_release_lock_sha256": lock_digest,
        "zebra_asset_sha256": zebra["asset"]["sha256"],
        "zebra_local_hold_exception": exception,
        "zebra_stage_receipt_sha256": digest(receipt_bytes),
        "snapshot_lock_sha256": snapshot_package.LOCK_SHA256,
        "snapshot_archive_sha256": snapshot_lock["archive_sha256"],
        "snapshot_manifest_signed": False,
        "binaries_sha256": {name: digest(data) for name, data in binaries.items()},
        "dockerfile_sha256": digest(dockerfile),
        "context_files_sha256": files_sha256,
        "context_sha256": digest(canonical(files_sha256)),
        "private_accepted": False,
        "deployment_enabled": False,
    }
    (output / "image-inputs.json").write_bytes(canonical(result))
    return result


def check_image_context(args):
    stock, zebra, lock_digest = locks()
    eligible, eligible_at = eligibility(zebra)
    directory = inside_workspace(args.context)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("regular image context directory required")
    expected_paths = set(CONTEXT_FILES) | {"image-inputs.json", "bin", "state", "vendor"}
    actual_paths = {str(path.relative_to(directory)) for path in directory.rglob("*")}
    if actual_paths != expected_paths or any(path.is_symlink() for path in directory.rglob("*")):
        raise ValueError("image context has missing, extra, or symlink paths")
    snapshot_package.check_context(directory)
    snapshot_lock, _ = snapshot_package.reviewed_lock()
    receipt = read_json(directory / "image-inputs.json")
    stage_receipt_bytes = regular_bytes(directory / "zebra-stage-receipt.json")
    stage_receipt = parse_json(stage_receipt_bytes)
    exception = checked_stage_receipt(stock, zebra, lock_digest, stage_receipt,
                                      digest(stage_receipt_bytes), eligible, eligible_at)
    files_sha256 = context_files_sha256(directory)
    if (zebra["zebrad_elf_sha256"] is None
            or zebra["zebrad_elf_size"] is None
            or files_sha256["bin/zebrad"] != zebra["zebrad_elf_sha256"]
            or (directory / "bin/zebrad").stat().st_size != zebra["zebrad_elf_size"]
            or any(files_sha256["bin/" + name] != expected
                   for name, expected in NATIVE_BINARIES_SHA256.items())
            or set(receipt) != {"schema_version", "status", "base_image",
                         "base_image_created_at", "stock_os_image_sha256",
                         "stock_candidate_lock_sha256", "zebra_release_lock_sha256",
                         "zebra_asset_sha256", "zebra_local_hold_exception",
                         "zebra_stage_receipt_sha256",
                         "snapshot_lock_sha256", "snapshot_archive_sha256",
                         "snapshot_manifest_signed",
                         "binaries_sha256",
                         "dockerfile_sha256", "context_files_sha256",
                         "context_sha256", "private_accepted", "deployment_enabled"}
            or receipt["schema_version"] != 1
            or receipt["status"] != "local-image-context-unapproved"
            or receipt["base_image"] != BASE_IMAGE
            or receipt["base_image_created_at"] != BASE_IMAGE_CREATED_AT
            or receipt["stock_os_image_sha256"] != stock["os_image_sha256"]
            or receipt["stock_candidate_lock_sha256"] != STOCK_LOCK_SHA256
            or receipt["zebra_release_lock_sha256"] != lock_digest
            or receipt["zebra_asset_sha256"] != zebra["asset"]["sha256"]
            or receipt["zebra_local_hold_exception"] != exception
            or receipt["zebra_stage_receipt_sha256"] != digest(stage_receipt_bytes)
            or receipt["snapshot_lock_sha256"] != snapshot_package.LOCK_SHA256
            or receipt["snapshot_archive_sha256"] != snapshot_lock["archive_sha256"]
            or receipt["snapshot_manifest_signed"] is not False
            or receipt["binaries_sha256"] != {
                "zebrad": zebra["zebrad_elf_sha256"], **NATIVE_BINARIES_SHA256}
            or receipt["dockerfile_sha256"] != files_sha256["Dockerfile"]
            or receipt["context_files_sha256"] != files_sha256
            or receipt["context_sha256"] != digest(canonical(files_sha256))
            or receipt["private_accepted"] is not False
            or receipt["deployment_enabled"] is not False
            or regular_bytes(directory / "Dockerfile") != dockerfile_bytes(BASE_IMAGE)
            or regular_bytes(directory / "supervisor.py") !=
            regular_bytes(HERE / "image/supervisor.py")
            or regular_bytes(directory / "zebra.toml") !=
            regular_bytes(HERE / "image/zebra.toml")
            or regular_bytes(directory / "state/.keep") != b""):
        raise ValueError("image context differs from reviewed inputs")
    return {
        "status": "local-image-context-checked-unapproved",
        "context_sha256": receipt["context_sha256"],
        "context_files_sha256": files_sha256,
        "base_image": BASE_IMAGE,
        "snapshot_lock_sha256": snapshot_package.LOCK_SHA256,
        "snapshot_archive_sha256": snapshot_lock["archive_sha256"],
        "snapshot_manifest_signed": False,
        "private_accepted": False,
        "deployment_enabled": False,
        "cloud_calls": False,
    }


def runtime_config(path):
    value = read_json(inside_workspace(path))
    required = {"quote_startup_timeout_secs", "node_startup_timeout_secs",
                "node_poll_interval_ms", "max_connections", "max_quotes",
                "quote_spacing_ms"}
    if (not isinstance(value, dict) or set(value) != required
            or any(type(value[name]) is not int or value[name] <= 0 for name in required)):
        raise ValueError("explicit positive runtime limits required")
    return value


def launch_documents(args):
    stock, zebra, lock_digest = locks()
    snapshot_lock, _ = snapshot_package.reviewed_lock()
    eligible, eligible_at = eligibility(zebra)
    if not eligible and not getattr(args, "allow_nu7_local_hold_exception", False):
        raise ValueError(f"Zebra release hold ends {eligible_at.isoformat()}")
    if not IMAGE_REF.fullmatch(args.image):
        raise ValueError("immutable application image reference required")
    inputs_path = inside_workspace(args.image_inputs)
    inputs_bytes = regular_bytes(inputs_path)
    inputs = parse_json(inputs_bytes)
    if (inputs.get("status") != "local-image-context-unapproved"
            or inputs.get("zebra_release_lock_sha256") != lock_digest
            or inputs.get("zebra_asset_sha256") != zebra["asset"]["sha256"]
            or inputs.get("stock_os_image_sha256") != stock["os_image_sha256"]
            or inputs.get("stock_candidate_lock_sha256") != STOCK_LOCK_SHA256
            or inputs.get("snapshot_lock_sha256") != snapshot_package.LOCK_SHA256
            or inputs.get("snapshot_archive_sha256") != snapshot_lock["archive_sha256"]
            or inputs.get("snapshot_manifest_signed") is not False
            or inputs.get("private_accepted") is not False
            or inputs.get("deployment_enabled") is not False):
        raise ValueError("image context receipt differs from reviewed inputs")
    if inputs_path.name != "image-inputs.json":
        raise ValueError("image context receipt path is not canonical")
    if not eligible:
        if (inputs.get("zebra_local_hold_exception") != LOCAL_HOLD_EXCEPTION
                or inputs.get("zebra_stage_receipt_sha256") !=
                stock["reviewed_zebra_local_hold_receipt_sha256"]):
            raise ValueError("Zebra local hold exception differs from reviewed receipt")
    check_image_context(argparse.Namespace(context=inputs_path.parent))
    if regular_bytes(inputs_path) != inputs_bytes:
        raise ValueError("image context receipt changed during verification")
    limits = runtime_config(args.runtime)
    base = {
        "image": args.image, "platform": "linux/amd64", "read_only": True,
        "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
        "logging": {"driver": "none"}, "restart": "no",
        "ulimits": {"core": 0},
        "tmpfs": ["/tmp:rw,nosuid,nodev,noexec,mode=1777"],
        "volumes": [{"type": "volume", "source": "runtime_tmpfs", "target": "/run"}],
    }
    quote = {
        **base, "user": "10002:0", "command": ["quote"],
        "network_mode": "none",
        "environment": {
            "QUOTE_STARTUP_TIMEOUT_SECS": str(limits["quote_startup_timeout_secs"]),
        },
        "volumes": base["volumes"] + [{
            "type": "bind", "source": "/run/dstack.sock", "target": "/dstack.sock",
            "read_only": True, "bind": {"create_host_path": False},
        }],
        "healthcheck": {
            "test": ["CMD", "python3", "/opt/zrpc/supervisor.py", "quote-health"],
        },
    }
    app = {
        **base, "user": "10001:0", "command": ["app"],
        "environment": {
            "NODE_STARTUP_TIMEOUT_SECS": str(limits["node_startup_timeout_secs"]),
            "NODE_POLL_INTERVAL_MS": str(limits["node_poll_interval_ms"]),
            "MAX_CONNECTIONS": str(limits["max_connections"]),
            "MAX_QUOTES": str(limits["max_quotes"]),
            "QUOTE_SPACING_MS": str(limits["quote_spacing_ms"]),
        },
        "ports": ["8443:8443"],
        "volumes": base["volumes"] + [{
            "type": "volume", "source": "zebra_public_testnet",
            "target": "/var/lib/zebra",
        }],
        "depends_on": {"quote": {"condition": "service_healthy"}},
    }
    compose = {
        "services": {"quote": quote, "app": app},
        "volumes": {
            "runtime_tmpfs": {"driver": "local", "driver_opts": {
                "type": "tmpfs", "device": "tmpfs", "o": "uid=0,gid=0,mode=1775",
            }},
            "zebra_public_testnet": {},
        },
    }
    compose_bytes = canonical(compose)
    app_compose = {
        "manifest_version": 2,
        "name": "zrpc-public-testnet-preview",
        "runner": "docker-compose",
        "docker_compose_file": compose_bytes.decode("ascii"),
        "storage_fs": "ext4",
        "kms_enabled": True,
        "tproxy_enabled": True,
        "public_logs": False,
        "public_sysinfo": False,
        "allowed_envs": [],
    }
    app_bytes = canonical(app_compose)
    output = fresh_output(args.output)
    output.mkdir()
    (output / "compose.json").write_bytes(compose_bytes)
    (output / "app-compose.json").write_bytes(app_bytes)
    result = {
        "schema_version": 1,
        "status": "local-launch-document-unapproved",
        "stock_os_image_sha256": stock["os_image_sha256"],
        "stock_candidate_lock_sha256": STOCK_LOCK_SHA256,
        "kms_catalog_id": stock["kms_catalog_id"],
        "zebra_release_lock_sha256": lock_digest,
        "zebra_local_hold_exception": inputs.get("zebra_local_hold_exception"),
        "zebra_stage_receipt_sha256": inputs.get("zebra_stage_receipt_sha256"),
        "snapshot_lock_sha256": snapshot_package.LOCK_SHA256,
        "snapshot_archive_sha256": snapshot_lock["archive_sha256"],
        "snapshot_manifest_signed": False,
        "image_ref": args.image,
        "image_inputs_sha256": digest(inputs_bytes),
        "docker_compose_file_sha256": digest(compose_bytes),
        "app_compose_file_sha256": digest(app_bytes),
        "tls_passthrough_port": 8443,
        "private_accepted": False,
        "deployment_enabled": False,
        "cloud_calls": False,
    }
    (output / "receipt.json").write_bytes(canonical(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    image = commands.add_parser("image-context")
    image.add_argument("--zebra-stage", required=True, type=Path)
    image.add_argument("--snapshot-wheel", required=True, type=Path)
    image.add_argument("--node-wrapper", required=True, type=Path)
    image.add_argument("--node-wrapper-sha256", required=True)
    image.add_argument("--quote-proxy", required=True, type=Path)
    image.add_argument("--quote-proxy-sha256", required=True)
    image.add_argument("--base-image", required=True)
    image.add_argument("--base-image-created-at", required=True)
    image.add_argument("--output", required=True, type=Path)
    image.add_argument("--allow-nu7-local-hold-exception", action="store_true")
    check_image = commands.add_parser("check-image-context")
    check_image.add_argument("--context", required=True, type=Path)
    launch = commands.add_parser("launch-documents")
    launch.add_argument("--image", required=True)
    launch.add_argument("--image-inputs", required=True, type=Path)
    launch.add_argument("--runtime", required=True, type=Path)
    launch.add_argument("--output", required=True, type=Path)
    launch.add_argument("--allow-nu7-local-hold-exception", action="store_true")
    args = parser.parse_args()
    try:
        stock, zebra, _ = locks()
        if args.command == "status":
            eligible, eligible_at = eligibility(zebra)
            snapshot_lock, _ = snapshot_package.reviewed_lock()
            result = {
                "status": "age-eligible-artifacts-still-unapproved" if eligible
                else "held-artifacts-unapproved",
                "stock_os_image_sha256": stock["os_image_sha256"],
                "stock_candidate_lock_sha256": STOCK_LOCK_SHA256,
                "kms_catalog_id": stock["kms_catalog_id"],
                "zebra_asset_sha256": zebra["asset"]["sha256"],
                "zebra_eligible_at_utc": eligible_at.isoformat().replace("+00:00", "Z"),
                "zebra_elf_identity_pinned": zebra["zebrad_elf_sha256"] is not None,
                "snapshot_lock_sha256": snapshot_package.LOCK_SHA256,
                "snapshot_archive_sha256": snapshot_lock["archive_sha256"],
                "snapshot_manifest_signed": False,
                "private_accepted": False,
                "deployment_enabled": False,
                "cloud_calls": False,
            }
        elif args.command == "image-context":
            result = image_context(args)
        elif args.command == "check-image-context":
            result = check_image_context(args)
        else:
            result = launch_documents(args)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "private_accepted": False, "deployment_enabled": False,
                          "cloud_calls": False}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
