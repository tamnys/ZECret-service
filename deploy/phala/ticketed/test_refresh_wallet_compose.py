"""Exact-image refresh must preserve every other measured launch byte."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("refresh_wallet_compose.py")
spec = importlib.util.spec_from_file_location("refresh_wallet_compose", SCRIPT)
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)
NEW_IMAGE = "ghcr.io/tamnys/zecret-service-preview@sha256:" + "b" * 64


class RefreshWalletComposeTests(unittest.TestCase):
    def test_only_app_and_issuer_images_change(self):
        with tempfile.TemporaryDirectory(dir=refresh.ROOT) as temporary:
            root = Path(temporary)
            output = root / "candidate"
            with mock.patch.object(refresh, "ROOT", root):
                receipt = refresh.prepare(NEW_IMAGE, output)
            original = json.loads(refresh.PREVIOUS.read_bytes())
            changed = json.loads((output / "app-compose.json").read_bytes())
            old_services = json.loads(original["docker_compose_file"])["services"]
            new_services = json.loads(changed["docker_compose_file"])["services"]
            self.assertEqual(changed["pre_launch_script"], original["pre_launch_script"])
            self.assertEqual(changed["allowed_envs"], original["allowed_envs"])
            self.assertEqual(new_services["quote"], old_services["quote"])
            for name in ("app", "issuer"):
                old_services[name]["image"] = NEW_IMAGE
            self.assertEqual(new_services, old_services)
            self.assertEqual(receipt["new_launch_sha256"], refresh.digest((output / "app-compose.json").read_bytes()))
            with self.assertRaisesRegex(ValueError, "fresh output directory"):
                refresh.prepare(NEW_IMAGE, output)

    def test_changed_source_and_unpinned_image_are_rejected(self):
        with tempfile.TemporaryDirectory(dir=refresh.ROOT) as temporary:
            root = Path(temporary)
            with mock.patch.object(refresh, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "new pinned wallet image"):
                    refresh.prepare("ghcr.io/tamnys/zecret-service-preview:latest", root / "uncreated")
                changed = root / "changed.json"
                changed.write_bytes(refresh.PREVIOUS.read_bytes() + b"\n")
                with mock.patch.object(refresh, "PREVIOUS", changed):
                    with self.assertRaisesRegex(ValueError, "identity differs"):
                        refresh.prepare(NEW_IMAGE, root / "uncreated")


if __name__ == "__main__":
    unittest.main()
