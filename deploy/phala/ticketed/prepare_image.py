#!/usr/bin/env python3
"""Build a checked, public-only context for the ticket-required Phala image."""

import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tarfile
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE_IMAGE = (
    "ghcr.io/tamnys/zecret-service-preview@sha256:"
    "a73f032681a26f8b2cb960cd32f355c478612e49ae657b5ca656f2b105fb4d78"
)
PUBLIC_HASHES = {
    "issuer-public.der": "7a55fad48f6f6be196cf4ad297c5e698dd871aadcba08480c3d83f83e6b04141",
    "hs_ed25519_public_key": "1497e796f86df39fb93d59e7da9e797a33e1591bf4eb106a89cd4ba464011466",
    "issuer-hostname": "4242db6234340f8e558567e96443ed94eeeefff7127c2d6f046669ebe0928109",
}
BINARIES = ("zrpc", "zrpc-node-wrapper", "zrpc-payment-crypto")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular_bytes(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("regular input required")
    return path.read_bytes()


def checked_native(bundle_path, bundle_sha256, revision):
    if not SHA256.fullmatch(bundle_sha256) or not COMMIT.fullmatch(revision):
        raise ValueError("native artifact identity is invalid")
    if not bundle_path.is_absolute() or not bundle_path.resolve().is_relative_to(ROOT):
        raise ValueError("native bundle must stay on the workspace volume")
    if digest(regular_bytes(bundle_path)) != bundle_sha256:
        raise ValueError("native artifact digest differs")
    with tarfile.open(bundle_path, "r:") as bundle:
        member = bundle.getmember("./manifest.json")
        if not member.isfile():
            raise ValueError("native manifest is invalid")
        manifest = json.load(bundle.extractfile(member))
        if manifest.get("source_commit") != revision:
            raise ValueError("native artifact source differs")
        pinned = manifest.get("artifact_sha256", {})
        binaries = {}
        for name in BINARIES:
            expected = pinned.get(name)
            member = bundle.getmember("./artifacts/" + name)
            if not isinstance(expected, str) or not SHA256.fullmatch(expected):
                raise ValueError("native binary is not pinned")
            if not member.isfile() or member.size <= 0:
                raise ValueError("native binary is not regular")
            data = bundle.extractfile(member).read()
            if (digest(data) != expected or len(data) < 20
                    or data[:6] != b"\x7fELF\x02\x01"
                    or data[18:20] != b"\x3e\x00"):
                raise ValueError("native x86_64 binary differs")
            binaries[name] = data
    return binaries


def checked_public():
    public = {}
    for name, expected in PUBLIC_HASHES.items():
        data = regular_bytes(HERE / name)
        if digest(data) != expected:
            raise ValueError("issuer public identity differs")
        public[name] = data
    key = public["hs_ed25519_public_key"]
    if len(key) != 64 or key[:32] != b"== ed25519v1-public: type0 ==\x00\x00\x00":
        raise ValueError("onion public key format differs")
    onion_key = key[32:]
    checksum = hashlib.sha3_256(b".onion checksum" + onion_key + b"\x03").digest()[:2]
    hostname = base64.b32encode(onion_key + checksum + b"\x03").decode("ascii").lower() + ".onion\n"
    if public["issuer-hostname"] != hostname.encode("ascii"):
        raise ValueError("onion hostname and public key differ")
    return public


def write(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def prepare(args):
    output = args.output
    if (not output.is_absolute() or not output.resolve().is_relative_to(ROOT)
            or output.exists() or output.is_symlink() or not output.parent.is_dir()):
        raise ValueError("fresh output directory on the workspace volume required")
    binaries = checked_native(args.native_bundle, args.native_bundle_sha256, args.revision)
    public = checked_public()
    spec = importlib.util.spec_from_file_location("stage_tor", HERE / "stage_tor.py")
    stage_tor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage_tor)
    with tempfile.TemporaryDirectory(prefix=".ticket-image-", dir=output.parent) as temporary:
        scratch = Path(temporary)
        tor_stage = scratch / "verified-tor"
        tor_receipt = stage_tor.stage(
            args.tor_archive, args.tor_signature, args.tor_signing_key, tor_stage
        )
        context = scratch / "context"
        context.mkdir()
        template = regular_bytes(HERE / "Dockerfile.in")
        prefix = b"ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n"
        if not template.startswith(prefix):
            raise ValueError("ticket image recipe differs")
        write(context / "Dockerfile", b"FROM " + BASE_IMAGE.encode() + b"\n"
              + template[len(prefix):], 0o644)
        write(context / "supervisor.py", regular_bytes(HERE.parent / "image/supervisor.py"), 0o644)
        write(context / "zebra.toml", regular_bytes(HERE.parent / "image/zebra.toml"), 0o644)
        for name, data in binaries.items():
            write(context / "bin" / name, data, 0o555)
        for name, data in public.items():
            write(context / "ticket" / name, data, 0o444)
        for name in stage_tor.SELECTED:
            write(context / "ticket" / name, regular_bytes(tor_stage / name),
                  stage_tor.SELECTED[name])
        for name in ("spent.keep", "issuer.keep"):
            write(context / "state" / name, b"", 0o600)
        files = sorted(str(path.relative_to(context)) for path in context.rglob("*") if path.is_file())
        receipt = {
            "schema": 1,
            "source_commit": args.revision,
            "base_image": BASE_IMAGE,
            "native_bundle_sha256": args.native_bundle_sha256,
            "tor": tor_receipt,
            "issuer_hostname": public["issuer-hostname"].decode("ascii").strip(),
            "files_sha256": {name: digest(regular_bytes(context / name)) for name in files},
        }
        write(context / "receipt.json",
              (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode(), 0o644)
        context.rename(output)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-bundle", required=True, type=Path)
    parser.add_argument("--native-bundle-sha256", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--tor-archive", required=True, type=Path)
    parser.add_argument("--tor-signature", required=True, type=Path)
    parser.add_argument("--tor-signing-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
