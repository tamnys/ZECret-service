"""Synthetic checks for the offline Phala preview package boundary."""

import argparse
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import socket
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("phala_prepare", HERE / "prepare.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
spec = importlib.util.spec_from_file_location(
    "phala_supervisor", HERE / "image/supervisor.py")
supervisor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(supervisor)


class PackageTests(unittest.TestCase):
    def setUp(self):
        scratch = prepare.ROOT / ".codex-tmp"
        scratch.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.wheel = self.root / "synthetic-zstandard.whl"
        self.wheel.write_bytes(b"synthetic wheel")

    def test_hold_blocks_image_context_before_creating_output(self):
        _, zebra, _ = prepare.locks()
        eligible, due = prepare.eligibility(
            zebra, datetime(2026, 10, 5, tzinfo=timezone.utc))
        self.assertFalse(eligible)
        self.assertEqual(due.isoformat(), "2026-10-09T00:18:54+00:00")
        args = argparse.Namespace(output=self.root / "context")
        with patch.object(prepare, "eligibility", return_value=(False, due)):
            with self.assertRaisesRegex(ValueError, "release hold"):
                prepare.image_context(args)
        self.assertFalse(args.output.exists())

    def test_stock_tuple_drift_blocks_rendering(self):
        altered = self.root / "stock.json"
        stock = prepare.read_json(prepare.STOCK_LOCK)
        stock["kms_endpoint"] = "https://changed.invalid"
        altered.write_bytes(prepare.canonical(stock))
        with patch.object(prepare, "STOCK_LOCK", altered):
            with self.assertRaisesRegex(ValueError, "stock or Zebra identity"):
                prepare.locks()

    def test_image_context_check_rejects_changed_build_inputs(self):
        stock, zebra, lock_digest = prepare.locks()
        eligible_at = prepare.utc(zebra["asset"]["created_at"]) + timedelta(days=7)
        elf = b"\x7fELF\x02\x01" + b"\x00" * 10 + b"\x03\x00\x3e\x00" + b"\x00" * 44
        elf_hash = prepare.digest(elf)
        zebra = {**zebra, "zebrad_elf_sha256": elf_hash, "zebrad_elf_size": len(elf)}
        native = {name: elf_hash for name in prepare.NATIVE_BINARIES_SHA256}
        stage = self.root / "stage"
        stage.mkdir()
        (stage / "zebrad").write_bytes(elf)
        (stage / "receipt.json").write_bytes(prepare.canonical({
            "schema_version": 1,
            "status": "staged-diagnostic-unapproved",
            "checked_at_utc": eligible_at.isoformat().replace("+00:00", "Z"),
            "eligible_at_utc": eligible_at.isoformat().replace("+00:00", "Z"),
            "archive_downloaded_by_tool": False,
            "image_built": False,
            "private_mode_approved": False,
            "local_hold_exception": None,
            "release_lock_sha256": lock_digest,
            "asset_sha256": zebra["asset"]["sha256"],
            "zebrad_elf_sha256": elf_hash,
            "zebrad_elf_size": len(elf),
            "verified_attestation_count": 1,
            "gh_verifier_executable_sha256": zebra["gh_verifier_executable_sha256"],
        }))
        for name in native:
            (self.root / name).write_bytes(elf)
        args = argparse.Namespace(
            zebra_stage=stage,
            snapshot_wheel=self.wheel,
            node_wrapper=self.root / "zrpc-node-wrapper",
            node_wrapper_sha256=elf_hash,
            quote_proxy=self.root / "zrpc-quote-proxy",
            quote_proxy_sha256=elf_hash,
            base_image=prepare.BASE_IMAGE,
            base_image_created_at=prepare.BASE_IMAGE_CREATED_AT,
            output=self.root / "context",
        )
        with (patch.object(prepare, "locks", return_value=(stock, zebra, lock_digest)),
              patch.object(prepare, "NATIVE_BINARIES_SHA256", native),
              patch.object(prepare.snapshot_package, "_checked_wheel",
                           side_effect=lambda path, _wheel: Path(path).read_bytes()),
              patch.object(prepare, "eligibility", return_value=(True, eligible_at))):
            prepare.image_context(args)
            checked = prepare.check_image_context(argparse.Namespace(context=args.output))
            self.assertEqual(checked["status"], "local-image-context-checked-unapproved")
            runtime = self.root / "runtime.json"
            runtime.write_bytes(prepare.canonical({
                "quote_startup_timeout_secs": 1,
                "node_startup_timeout_secs": 1,
                "node_poll_interval_ms": 1,
                "max_connections": 1,
                "max_quotes": 1,
                "quote_spacing_ms": 1,
            }))
            render_args = argparse.Namespace(
                image="registry.example.invalid/zrpc@sha256:" + "a" * 64,
                image_inputs=args.output / "image-inputs.json",
                runtime=runtime,
                output=self.root / "rejected-launch",
            )
            (args.output / "supervisor.py").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "reviewed inputs"):
                prepare.check_image_context(argparse.Namespace(context=args.output))
            with self.assertRaisesRegex(ValueError, "reviewed inputs"):
                prepare.launch_documents(render_args)
            self.assertFalse(render_args.output.exists())
            (args.output / "supervisor.py").write_bytes(
                (prepare.HERE / "image/supervisor.py").read_bytes())
            (args.output / "snapshot.lock.json").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "snapshot image input"):
                prepare.check_image_context(argparse.Namespace(context=args.output))
            (args.output / "snapshot.lock.json").write_bytes(
                (prepare.HERE / "snapshot.lock.json").read_bytes())
            native_file = args.output / "bin/zrpc-node-wrapper"
            native_file.chmod(0o755)
            native_file.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "reviewed inputs"):
                prepare.check_image_context(argparse.Namespace(context=args.output))
            native_file.write_bytes(elf)
            (args.output / ".dockerignore").write_text("bin/\n")
            with self.assertRaisesRegex(ValueError, "missing, extra"):
                prepare.check_image_context(argparse.Namespace(context=args.output))

    def test_exact_stage_exception_allows_local_context_only(self):
        stock, zebra, lock_digest = prepare.locks()
        due = prepare.utc(zebra["asset"]["created_at"]) + timedelta(days=7)
        checked = due - timedelta(days=1)
        elf = b"\x7fELF\x02\x01" + b"\x00" * 10 + b"\x03\x00\x3e\x00" + b"\x00" * 44
        elf_hash = prepare.digest(elf)
        zebra = {**zebra, "zebrad_elf_sha256": elf_hash, "zebrad_elf_size": len(elf)}
        native = {name: elf_hash for name in prepare.NATIVE_BINARIES_SHA256}
        stage = self.root / "stage"
        stage.mkdir()
        (stage / "zebrad").write_bytes(elf)
        receipt = {
            "schema_version": 1,
            "status": "staged-diagnostic-unapproved",
            "checked_at_utc": checked.isoformat().replace("+00:00", "Z"),
            "eligible_at_utc": due.isoformat().replace("+00:00", "Z"),
            "archive_downloaded_by_tool": False,
            "image_built": False,
            "private_mode_approved": False,
            "local_hold_exception": prepare.LOCAL_HOLD_EXCEPTION,
            "release_lock_sha256": lock_digest,
            "asset_sha256": zebra["asset"]["sha256"],
            "zebrad_elf_sha256": elf_hash,
            "zebrad_elf_size": len(elf),
            "verified_attestation_count": 1,
            "gh_verifier_executable_sha256": zebra["gh_verifier_executable_sha256"],
        }
        (stage / "receipt.json").write_bytes(prepare.canonical(receipt))
        synthetic_receipt_hash = prepare.digest((stage / "receipt.json").read_bytes())
        for name in native:
            (self.root / name).write_bytes(elf)
        args = argparse.Namespace(
            zebra_stage=stage,
            snapshot_wheel=self.wheel,
            node_wrapper=self.root / "zrpc-node-wrapper",
            node_wrapper_sha256=elf_hash,
            quote_proxy=self.root / "zrpc-quote-proxy",
            quote_proxy_sha256=elf_hash,
            base_image=prepare.BASE_IMAGE,
            base_image_created_at=prepare.BASE_IMAGE_CREATED_AT,
            output=self.root / "context",
            allow_nu7_evaluation_hold_exception=True,
        )
        with (patch.object(prepare, "locks", return_value=(stock, zebra, lock_digest)),
              patch.object(prepare, "NATIVE_BINARIES_SHA256", native),
              patch.object(prepare.snapshot_package, "_checked_wheel",
                           side_effect=lambda path, _wheel: Path(path).read_bytes()),
              patch.object(prepare, "eligibility", return_value=(False, due))):
            with self.assertRaisesRegex(ValueError, "approved asset"):
                prepare.image_context(args)
        stock = {**stock, "reviewed_zebra_local_hold_receipt_sha256":
                 synthetic_receipt_hash}
        with (patch.object(prepare, "locks", return_value=(stock, zebra, lock_digest)),
              patch.object(prepare, "NATIVE_BINARIES_SHA256", native),
              patch.object(prepare.snapshot_package, "_checked_wheel",
                           side_effect=lambda path, _wheel: Path(path).read_bytes()),
              patch.object(prepare, "eligibility", return_value=(False, due))):
            context = prepare.image_context(args)
            self.assertEqual(context["zebra_local_hold_exception"],
                             prepare.LOCAL_HOLD_EXCEPTION)
            self.assertEqual(context["zebra_stage_receipt_sha256"],
                             synthetic_receipt_hash)
            self.assertEqual(prepare.check_image_context(
                argparse.Namespace(context=args.output))["status"],
                "local-image-context-checked-unapproved")
            runtime = self.root / "runtime.json"
            runtime.write_bytes(prepare.canonical({
                "quote_startup_timeout_secs": 1,
                "node_startup_timeout_secs": 1,
                "node_poll_interval_ms": 1,
                "max_connections": 1,
                "max_quotes": 1,
                "quote_spacing_ms": 1,
            }))
            inputs_path = args.output / "image-inputs.json"
            inputs_bytes = inputs_path.read_bytes()
            render_args = argparse.Namespace(
                image="registry.example.invalid/zrpc@sha256:" + "a" * 64,
                image_inputs=inputs_path,
                runtime=runtime,
                output=self.root / "launch",
                allow_nu7_evaluation_hold_exception=False,
            )
            with self.assertRaisesRegex(ValueError, "release hold"):
                prepare.launch_documents(render_args)
            render_args.allow_nu7_evaluation_hold_exception = True
            inputs = prepare.parse_json(inputs_bytes)
            inputs["zebra_stage_receipt_sha256"] = "0" * 64
            inputs_path.write_bytes(prepare.canonical(inputs))
            with self.assertRaisesRegex(ValueError, "reviewed receipt"):
                prepare.launch_documents(render_args)
            inputs["zebra_stage_receipt_sha256"] = synthetic_receipt_hash
            inputs["zebra_local_hold_exception"] = {
                **prepare.LOCAL_HOLD_EXCEPTION, "asset_id": 1}
            inputs_path.write_bytes(prepare.canonical(inputs))
            with self.assertRaisesRegex(ValueError, "reviewed receipt"):
                prepare.launch_documents(render_args)
            inputs_path.write_bytes(inputs_bytes)
            receipt["local_hold_exception"] = {
                **prepare.LOCAL_HOLD_EXCEPTION, "asset_id": 1}
            (args.output / "zebra-stage-receipt.json").write_bytes(
                prepare.canonical(receipt))
            with self.assertRaisesRegex(ValueError, "approved asset"):
                prepare.launch_documents(render_args)
            (args.output / "zebra-stage-receipt.json").write_bytes(
                (stage / "receipt.json").read_bytes())
            rendered = prepare.launch_documents(render_args)
            self.assertEqual(rendered["zebra_local_hold_exception"],
                             prepare.LOCAL_HOLD_EXCEPTION)
            self.assertEqual(rendered["zebra_stage_receipt_sha256"],
                             synthetic_receipt_hash)
            self.assertFalse(rendered["private_accepted"])
            self.assertFalse(rendered["deployment_enabled"])
            self.assertFalse(rendered["cloud_calls"])

    def test_render_binds_exact_bytes_and_isolates_backend_socket(self):
        stock, zebra, lock_digest = prepare.locks()
        snapshot_lock, _ = prepare.snapshot_package.reviewed_lock()
        inputs = self.root / "image-inputs.json"
        inputs.write_bytes(prepare.canonical({
            "status": "local-image-context-unapproved",
            "zebra_release_lock_sha256": lock_digest,
            "zebra_asset_sha256": zebra["asset"]["sha256"],
            "stock_os_image_sha256": stock["os_image_sha256"],
            "stock_candidate_lock_sha256": prepare.STOCK_LOCK_SHA256,
            "snapshot_lock_sha256": prepare.snapshot_package.LOCK_SHA256,
            "snapshot_archive_sha256": snapshot_lock["archive_sha256"],
            "snapshot_manifest_signed": False,
            "private_accepted": False,
            "deployment_enabled": False,
        }))
        runtime = self.root / "runtime.json"
        runtime.write_bytes(prepare.canonical({
            "quote_startup_timeout_secs": 1,
            "node_startup_timeout_secs": 1,
            "node_poll_interval_ms": 1,
            "max_connections": 1,
            "max_quotes": 1,
            "quote_spacing_ms": 1,
        }))
        image = "registry.example.invalid/zrpc@sha256:" + "a" * 64
        args = argparse.Namespace(image=image, image_inputs=inputs, runtime=runtime,
                                  output=self.root / "render")
        with (patch.object(prepare, "eligibility",
                           return_value=(True, datetime.now(timezone.utc))),
              patch.object(prepare, "check_image_context") as checked_context):
            receipt = prepare.launch_documents(args)
            checked_context.assert_called_once()
            self.assertEqual(checked_context.call_args.args[0].context, inputs.parent)
        compose_bytes = (args.output / "compose.json").read_bytes()
        app_bytes = (args.output / "app-compose.json").read_bytes()
        compose = json.loads(compose_bytes)
        app = json.loads(app_bytes)
        self.assertEqual(app["docker_compose_file"].encode(), compose_bytes)
        # dstack 0.5.9 defaults omitted swap_size to zero; the current Phala
        # AppComposeV2 API does not declare this field. Supervisor rechecks
        # /proc/swaps before either service starts.
        self.assertNotIn("swap_size", app)
        self.assertNotIn("key_provider", app)
        self.assertEqual(receipt["docker_compose_file_sha256"], prepare.digest(compose_bytes))
        self.assertEqual(receipt["app_compose_file_sha256"], prepare.digest(app_bytes))
        self.assertEqual(compose["services"]["app"]["ports"], ["8443:8443"])
        self.assertEqual(compose["services"]["quote"]["network_mode"], "none")
        self.assertEqual(compose["services"]["quote"]["user"], "10002:0")
        self.assertEqual(compose["services"]["app"]["user"], "10001:0")
        self.assertEqual(compose["services"]["app"]["image"], image)
        self.assertEqual(compose["services"]["quote"]["image"], image)
        self.assertEqual(compose["volumes"]["runtime_tmpfs"]["driver_opts"]["type"], "tmpfs")
        for service in ("quote", "app"):
            self.assertEqual(compose["services"][service]["ulimits"]["core"], 0)
            self.assertEqual(compose["services"][service]["tmpfs"],
                             ["/tmp:rw,nosuid,nodev,noexec,mode=1777"])
        quote_bind = compose["services"]["quote"]["volumes"][1]
        self.assertEqual(quote_bind["source"], "/run/dstack.sock")
        self.assertEqual(quote_bind["target"], "/dstack.sock")
        self.assertNotIn("/dstack.sock", json.dumps(compose["services"]["app"]))
        self.assertNotIn("/run/dstack.sock", json.dumps(compose["services"]["app"]))
        self.assertFalse(receipt["private_accepted"])
        self.assertFalse(receipt["deployment_enabled"])
        self.assertFalse(receipt["cloud_calls"])

    def test_mutable_image_and_missing_limits_refuse_render(self):
        runtime = self.root / "runtime.json"
        runtime.write_text('{"max_connections":1}')
        with self.assertRaisesRegex(ValueError, "runtime limits"):
            prepare.runtime_config(runtime)
        self.assertIsNone(prepare.IMAGE_REF.fullmatch("registry.example.invalid/zrpc:latest"))

    def test_quote_health_requires_marker_and_both_actual_sockets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            quote = root / "zrpc-quote"
            quote.mkdir()
            marker = root / "zrpc-quote-ready"
            marker.write_bytes(b"")
            marker.chmod(0o600)
            sockets = []
            try:
                for name in ("quote.sock", "watch.sock"):
                    item = socket.socket(socket.AF_UNIX)
                    item.bind(str(quote / name))
                    (quote / name).chmod(0o660)
                    sockets.append(item)
                with patch.object(supervisor, "RUN", root), patch.object(
                    supervisor, "QUOTE_READY", marker
                ):
                    self.assertTrue(supervisor.quote_health())
                    (quote / "watch.sock").unlink()
                    self.assertFalse(supervisor.quote_health())
            finally:
                for item in sockets:
                    item.close()

    def test_app_startup_refuses_legacy_shared_backend_socket(self):
        with socket.socket(socket.AF_UNIX) as backend:
            backend.bind(str(self.root / "dstack.sock"))
            snapshot = types.ModuleType("snapshot_import")
            snapshot.ensure_snapshot = lambda: None
            with (patch.dict(sys.modules, {"snapshot_import": snapshot}),
                  patch.object(supervisor, "RUN", self.root),
                  patch.object(supervisor, "BACKEND", self.root / "quote-only.sock"),
                  patch.object(supervisor.resource, "getrlimit", return_value=(0, 0)),
                  patch.object(supervisor, "mount_type", return_value="tmpfs")):
                with self.assertRaisesRegex(RuntimeError, "app container exposes dstack socket"):
                    supervisor.run_app()

    def test_split_node_refuses_quote_socket_before_snapshot_import(self):
        quote_dir = self.root / "zrpc-quote"
        quote_dir.mkdir()
        with socket.socket(socket.AF_UNIX) as quote:
            quote.bind(str(quote_dir / "quote.sock"))
            snapshot = types.ModuleType("snapshot_import")
            snapshot.ensure_snapshot = Mock()
            with (patch.dict(sys.modules, {"snapshot_import": snapshot}),
                  patch.object(supervisor, "RUN", self.root),
                  patch.object(supervisor, "BACKEND", self.root / "dstack-backend"),
                  patch.object(supervisor.resource, "getrlimit", return_value=(0, 0)),
                  patch.object(supervisor, "mount_type", return_value="tmpfs"),
                  patch.object(supervisor.subprocess, "Popen") as started):
                with self.assertRaisesRegex(RuntimeError, "guest control socket path"):
                    supervisor.run_node()
                snapshot.ensure_snapshot.assert_not_called()
                started.assert_not_called()

    def test_split_node_refuses_stale_cookie_before_snapshot_import(self):
        state = self.root / "state"
        state.mkdir(mode=0o700)
        cookie_dir = self.root / "zrpc-node"
        cookie_dir.mkdir(mode=0o700)
        cookie = cookie_dir / ".cookie"
        cookie.write_bytes(b"stale")
        snapshot = types.ModuleType("snapshot_import")
        snapshot.ensure_snapshot = Mock()
        with (patch.dict(sys.modules, {"snapshot_import": snapshot}),
              patch.object(supervisor, "RUN", self.root),
              patch.object(supervisor, "STATE", state),
              patch.object(supervisor, "COOKIE_DIR", cookie_dir),
              patch.object(supervisor, "COOKIE", cookie),
              patch.object(supervisor, "BACKEND", self.root / "dstack-backend"),
              patch.object(supervisor.resource, "getrlimit", return_value=(0, 0)),
              patch.object(supervisor, "mount_type",
                           side_effect=lambda path: "tmpfs" if path in (self.root, Path("/tmp")) else "ext4"),
              patch.object(supervisor.subprocess, "Popen") as started):
            with self.assertRaisesRegex(RuntimeError, "stale Zebra RPC cookie"):
                supervisor.run_node()
            snapshot.ensure_snapshot.assert_not_called()
            started.assert_not_called()
            self.assertEqual((self.root / "zrpc-quote").stat().st_mode & 0o777, 0o700)

    def test_split_node_refuses_preexisting_quote_mountpoint(self):
        (self.root / "zrpc-quote").mkdir()
        snapshot = types.ModuleType("snapshot_import")
        snapshot.ensure_snapshot = Mock()
        with (patch.dict(sys.modules, {"snapshot_import": snapshot}),
              patch.object(supervisor, "RUN", self.root),
              patch.object(supervisor, "BACKEND", self.root / "dstack-backend"),
              patch.object(supervisor.resource, "getrlimit", return_value=(0, 0)),
              patch.object(supervisor, "mount_type", return_value="tmpfs"),
              patch.object(supervisor.subprocess, "Popen") as started):
            with self.assertRaises(FileExistsError):
                supervisor.run_node()
            snapshot.ensure_snapshot.assert_not_called()
            started.assert_not_called()

    def test_split_node_health_requires_cookie_rpc_and_no_quote_socket(self):
        cookie = self.root / ".cookie"
        cookie.write_bytes(b"synthetic")
        cookie.chmod(0o600)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as node:
            node.bind(("127.0.0.1", 0))
            node.listen(1)
            with (patch.object(supervisor, "RUN", self.root),
                  patch.object(supervisor, "COOKIE", cookie),
                  patch.object(supervisor, "BACKEND", self.root / "dstack-backend"),
                  patch.object(supervisor, "NODE_RPC", node.getsockname()),
                  patch.dict(supervisor.os.environ, {"NODE_POLL_INTERVAL_MS": "1000"}),
                  patch.object(supervisor, "mount_type", return_value="tmpfs")):
                self.assertTrue(supervisor.node_health())
                quote_dir = self.root / "zrpc-quote"
                quote_dir.mkdir()
                with socket.socket(socket.AF_UNIX) as quote:
                    quote.bind(str(quote_dir / "quote.sock"))
                    self.assertFalse(supervisor.node_health())
                (quote_dir / "quote.sock").unlink()
                cookie.chmod(0o644)
                self.assertFalse(supervisor.node_health())

    def test_split_wrapper_refuses_missing_quote_bridge(self):
        with (patch.object(supervisor, "RUN", self.root),
              patch.object(supervisor, "BACKEND", self.root / "dstack-backend"),
              patch.object(supervisor, "mount_type", return_value="tmpfs"),
              patch.object(supervisor.subprocess, "Popen") as started):
            with self.assertRaisesRegex(RuntimeError, "quote-only bridge"):
                supervisor.run_wrapper()
            started.assert_not_called()

    def test_split_modes_refuse_root_group_before_any_startup(self):
        with (patch.object(supervisor.os, "getegid", return_value=0),
              patch.object(supervisor, "require_runtime_mount") as mounted,
              patch.object(supervisor.subprocess, "Popen") as started):
            for mode in (supervisor.run_node, supervisor.run_wrapper):
                with self.subTest(mode=mode.__name__):
                    with self.assertRaisesRegex(RuntimeError, "non-root identity"):
                        mode()
            mounted.assert_not_called()
            started.assert_not_called()

    def test_split_modes_are_explicit(self):
        for mode, method in (("node", "run_node"), ("wrapper", "run_wrapper")):
            with (patch.object(sys, "argv", ["supervisor.py", mode]),
                  patch.object(supervisor, method) as started):
                self.assertEqual(supervisor.main(), 1)
                started.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
