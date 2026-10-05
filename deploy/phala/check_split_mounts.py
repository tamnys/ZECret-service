#!/usr/bin/env python3
"""Native Docker smoke for the unapproved split Phala image modes.

The quote and snapshot marker are synthetic. This does not boot dstack or TDX,
establish a production mount policy, or authorize private RPC requests.
"""

import argparse
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

spec = importlib.util.spec_from_file_location(
    "phala_native_mount_smoke", Path(__file__).with_name("check_native_mounts.py"))
stock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stock)


SYNTHETIC_MARKER = r"""
import hashlib
import json
from pathlib import Path

lock = Path('/opt/zrpc/snapshot.lock.json')
raw = lock.read_bytes()
expected = 'be9d8781d86b9dff803f18d5caf0fc56ec5b3457bca0731fc444f8a4c62960fe'
assert hashlib.sha256(raw).hexdigest() == expected
value = json.loads(raw)
published = Path('/var/lib/zebra/state')
published.mkdir(mode=0o700)
marker = {'archive_sha256': value['archive_sha256'],
          'snapshot_lock_sha256': expected}
(published / '.zrpc-snapshot-import.json').write_text(
    json.dumps(marker, sort_keys=True, separators=(',', ':')))
print('Synthetic snapshot marker installed for cold Zebra smoke', flush=True)
"""

NODE_ISOLATION = r"""
from pathlib import Path
quote_dir = Path('/run/zrpc-quote')
assert quote_dir.is_dir() and not any(quote_dir.iterdir())
assert not Path('/dstack.sock').exists()
assert not Path('/run/dstack.sock').exists()
print('Zebra container has no guest quote or control socket', flush=True)
"""


def output(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def ready(name, user, mode, environment=None):
    command = ["docker", "exec", "--user", user]
    if environment is not None:
        command += ["--env", environment]
    command += [name, "python3", "/opt/zrpc/supervisor.py", mode]
    while True:
        result = subprocess.run(command,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            return
        if output("inspect", "--format", "{{.State.Running}}", name) != "true":
            stock.docker("logs", name)
            raise RuntimeError(f"{name} stopped before readiness")
        time.sleep(0.1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    suffix = uuid.uuid4().hex
    runtime = f"zrpc-split-runtime-{suffix}"
    quote_runtime = f"zrpc-split-quote-{suffix}"
    state = f"zrpc-split-state-{suffix}"
    backend_name = f"zrpc-split-backend-{suffix}"
    quote_name = f"zrpc-split-bridge-{suffix}"
    node_name = f"zrpc-split-node-{suffix}"
    wrapper_name = f"zrpc-split-wrapper-{suffix}"
    label = f"zrpc.split-smoke={suffix}"
    try:
        stock.docker("volume", "create", "--label", label,
                     "--driver", "local", "--opt", "type=tmpfs",
                     "--opt", "device=tmpfs",
                     "--opt", "o=uid=10001,gid=10001,mode=0700", runtime)
        stock.docker("volume", "create", "--label", label,
                     "--driver", "local", "--opt", "type=tmpfs",
                     "--opt", "device=tmpfs",
                     "--opt", "o=uid=0,gid=10001,mode=0750", quote_runtime)
        stock.docker("volume", "create", "--label", label, state)
        with tempfile.TemporaryDirectory(prefix="zrpc-split-smoke-") as directory:
            backend = Path(directory) / "stock-dstack.sock"
            stock.docker(
                "run", "--detach", "--name", backend_name, "--label", label,
                "--pull=never",
                "--network", "none", "--read-only", "--user", "0:0",
                "--mount", f"type=bind,source={directory},target=/backend",
                "--entrypoint", "python3", args.image, "-I", "-c",
                stock.ROOT_BACKEND_CHECK,
            )
            with subprocess.Popen(["docker", "logs", "--follow", backend_name],
                                  stdout=subprocess.PIPE, text=True) as logs:
                if logs.stdout.readline().strip() != "READY":
                    raise RuntimeError("synthetic root backend stopped before readiness")
                logs.terminate()
            if backend.stat().st_uid != 0:
                raise AssertionError("synthetic backend is not root-owned")

            # The fixture value exercises startup, not a deployment timeout.
            stock.docker(
                "run", "--detach", "--name", quote_name, "--label", label,
                "--pull=never",
                "--network", "none", "--read-only", "--cap-drop=ALL",
                "--security-opt", "no-new-privileges:true", "--user", "0:10001",
                "--env", "QUOTE_STARTUP_TIMEOUT_SECS=1",
                "--mount", f"type=volume,source={quote_runtime},target=/run",
                "--mount", f"type=bind,source={backend},target=/dstack.sock,readonly",
                args.image, "quote",
            )
            ready(quote_name, "0:10001", "quote-health")

            stock.docker(
                "run", "--rm", "--pull=never", "--network", "none",
                "--read-only", "--user", "10001:10001",
                "--mount", f"type=volume,source={state},target=/var/lib/zebra",
                "--entrypoint", "python3", args.image, "-I", "-c",
                SYNTHETIC_MARKER,
            )
            stock.docker(
                "run", "--detach", "--name", node_name, "--label", label,
                "--pull=never",
                "--network", "bridge", "--read-only", "--cap-drop=ALL",
                "--security-opt", "no-new-privileges:true", "--user", "10001:10001",
                "--mount", f"type=volume,source={runtime},target=/run",
                "--mount", f"type=volume,source={state},target=/var/lib/zebra",
                args.image, "node",
            )
            ready(node_name, "10001:10001", "node-health",
                  "NODE_POLL_INTERVAL_MS=1")
            stock.docker("exec", "--user", "10001:10001", node_name,
                         "python3", "-I", "-c", NODE_ISOLATION)
            stock.docker("exec", "--user", "10001:10001", node_name,
                         "python3", "-I", "-c", stock.ZEBRA_RPC_CHECK)

            quote_mount = output("volume", "inspect", "--format",
                                 "{{.Mountpoint}}", quote_runtime)
            quote_dir = str(Path(quote_mount) / "zrpc-quote")
            # These are synthetic CLI minima, not selected runtime limits.
            stock.docker(
                "run", "--detach", "--name", wrapper_name, "--label", label,
                "--pull=never",
                "--network", f"container:{node_name}", "--read-only",
                "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
                "--user", "10001:10001",
                "--env", "NODE_STARTUP_TIMEOUT_SECS=1",
                "--env", "NODE_POLL_INTERVAL_MS=1",
                "--env", "MAX_CONNECTIONS=1", "--env", "MAX_QUOTES=1",
                "--env", "QUOTE_SPACING_MS=1",
                "--mount", f"type=volume,source={runtime},target=/run,readonly",
                "--mount", (f"type=bind,source={quote_dir},"
                            "target=/run/zrpc-quote,readonly"),
                args.image, "wrapper",
            )
            stock.docker("exec", "--user", "10001:10001", node_name,
                         "python3", "-I", "-c", NODE_ISOLATION)
            while True:
                probe = subprocess.run(
                    ["docker", "exec", "--user", "10001:10001", node_name,
                     "python3", "-I", "-c", stock.WRAPPER_TLS_CHECK],
                    capture_output=True, text=True,
                )
                if probe.returncode == 0:
                    break
                if probe.returncode != 75:
                    raise RuntimeError(f"wrapper TLS probe failed: {probe.stderr}")
                if output("inspect", "--format", "{{.State.Running}}",
                          wrapper_name) != "true":
                    stock.docker("logs", wrapper_name)
                    raise RuntimeError("split wrapper stopped before TLS readiness")
                time.sleep(0.1)
            stock.docker("exec", "--user", "10001:10001", node_name,
                         "python3", "-I", "-c", stock.WRAPPER_PUBLIC_RPC_CHECK)

            held = subprocess.Popen(
                ["docker", "exec", "--user", "10001:10001", node_name,
                 "python3", "-I", "-c", stock.WRAPPER_HELD_SESSION_CHECK],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                if held.stdout.readline().strip() != "SESSION_READY":
                    _, error = held.communicate()
                    raise RuntimeError(f"split held session did not start: {error}")
                stock.docker("rm", "--force", quote_name)
                stopped = subprocess.run(["docker", "wait", wrapper_name],
                                         capture_output=True, text=True, check=True)
                if stopped.stdout.strip() != "1":
                    raise AssertionError("split wrapper survived quote bridge loss")
                result, error = held.communicate()
                if held.returncode != 0 or result.strip() != "SESSION_CLOSED":
                    raise AssertionError(f"split TLS session survived bridge loss: {error}")
            finally:
                if held.poll() is None:
                    held.terminate()
                    held.communicate()
            stock.docker("exec", "--user", "10001:10001", node_name,
                         "python3", "-I", "-c", stock.WRAPPER_DOWN_CHECK)
        print("Split node/wrapper native smoke passed with synthetic quote and marker; "
              "private_accepted=false")
    finally:
        for name in output("ps", "--all", "--quiet", "--filter",
                           f"label={label}").splitlines():
            stock.docker("rm", "--force", name)
        for name in output("volume", "ls", "--quiet", "--filter",
                           f"label={label}").splitlines():
            stock.docker("volume", "rm", name)
        if (output("ps", "--all", "--quiet", "--filter", f"label={label}")
                or output("volume", "ls", "--quiet", "--filter",
                          f"label={label}")):
            raise RuntimeError("synthetic split-smoke resources remain after cleanup")


if __name__ == "__main__":
    main()
