#!/usr/bin/env python3
"""Refresh only the app and issuer image in the reviewed wallet launch."""

import argparse
import hashlib
import json
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PREVIOUS = HERE.parent / "releases/2026-10-05/issuer-rotated-wallet-app-compose.json"
PREVIOUS_SHA256 = "1badb7bda92f4fca395ba25eb0fdddfd967de24c3e05a3435c33b6f1663f2108"
PREVIOUS_INNER_SHA256 = "79f449c78aacb866739911a784340be1c14b248add068dec06bb509fd7377906"
PREVIOUS_IMAGE = (
    "ghcr.io/tamnys/zecret-service-preview@sha256:"
    "6c26db81cf6c0d2f9962b979cce2c1c25b14535ec2ea53f9f216e71a3e336336"
)
QUOTE_IMAGE = (
    "ghcr.io/tamnys/zecret-service-preview@sha256:"
    "a73f032681a26f8b2cb960cd32f355c478612e49ae657b5ca656f2b105fb4d78"
)
IMAGE = re.compile(r"ghcr\.io/tamnys/zecret-service-preview@sha256:[0-9a-f]{64}\Z")
SECRETS = ["ZRPC_ISSUER_PRIVATE_DER_B64", "ZRPC_ONION_SECRET_KEY_B64"]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def prepare(image_ref, output):
    if not IMAGE.fullmatch(image_ref) or image_ref in (PREVIOUS_IMAGE, QUOTE_IMAGE):
        raise ValueError("new pinned wallet image required")
    if (not output.is_absolute() or not output.resolve().is_relative_to(ROOT)
            or output.exists() or output.is_symlink() or not output.parent.is_dir()):
        raise ValueError("fresh output directory on workspace volume required")
    old_bytes = PREVIOUS.read_bytes()
    if digest(old_bytes) != PREVIOUS_SHA256:
        raise ValueError("reviewed wallet launch identity differs")
    outer = json.loads(old_bytes)
    if (canonical(outer) != old_bytes or outer.get("allowed_envs") != SECRETS
            or outer.get("public_logs") is not False
            or outer.get("public_sysinfo") is not False
            or outer.get("storage_fs") != "ext4"):
        raise ValueError("reviewed wallet launch shape differs")
    old_inner = outer["docker_compose_file"].encode("ascii")
    if digest(old_inner) != PREVIOUS_INNER_SHA256:
        raise ValueError("reviewed wallet service identity differs")
    inner = json.loads(old_inner)
    if (canonical(inner) != old_inner or set(inner.get("services", {})) != {"app", "issuer", "quote"}
            or any(inner["services"][name].get("image") != PREVIOUS_IMAGE
                   for name in ("app", "issuer"))
            or inner["services"]["quote"].get("image") != QUOTE_IMAGE
            or inner["services"]["app"].get("command") != ["ticketed-app"]
            or inner["services"]["issuer"].get("command") != ["issuer"]):
        raise ValueError("reviewed wallet service set differs")
    for name in ("app", "issuer"):
        inner["services"][name]["image"] = image_ref
    inner_bytes = canonical(inner)
    outer["docker_compose_file"] = inner_bytes.decode("ascii")
    outer_bytes = canonical(outer)
    output.mkdir()
    (output / "compose.json").write_bytes(inner_bytes)
    (output / "app-compose.json").write_bytes(outer_bytes)
    receipt = {
        "schema": 1,
        "previous_launch_sha256": PREVIOUS_SHA256,
        "previous_compose_sha256": PREVIOUS_INNER_SHA256,
        "new_launch_sha256": digest(outer_bytes),
        "new_compose_sha256": digest(inner_bytes),
        "previous_image": PREVIOUS_IMAGE,
        "new_image": image_ref,
        "quote_image": QUOTE_IMAGE,
        "changed_services": ["app", "issuer"],
    }
    (output / "receipt.json").write_bytes(canonical(receipt) + b"\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.image_ref, args.output), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
