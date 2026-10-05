"""Synthetic, networkless negative cases for the Cargo registry preflight."""

import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("check-cargo-registry-age.py")
spec = importlib.util.spec_from_file_location("check_cargo_registry_age", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


NOW = dt.datetime(2026, 9, 27, 19, 0, 0, tzinfo=dt.timezone.utc)
CHECKSUM = "a" * 64


def entry(*, name="sample", version="1.2.3", checksum=CHECKSUM,
          published="2026-09-19T19:00:00Z", yanked=False):
    return json.dumps({"name": name, "vers": version, "cksum": checksum,
                       "pubtime": published, "yanked": yanked})


class CargoRegistryGateTests(unittest.TestCase):
    def test_sparse_index_path_rules(self):
        self.assertEqual([gate.index_path(name) for name in ("a", "ab", "abc", "AbCd")],
                         ["1/a", "2/ab", "3/a/abc", "ab/cd/abcd"])

    def test_live_record_must_match_lock_checksum_and_yank_status(self):
        for response, reason in (
            (entry(checksum="b" * 64), "checksum mismatch"),
            (entry(yanked=True), "yanked"),
            (entry(yanked=None), "yanked"),
            (entry(name="other"), "identity mismatch"),
            (entry(published=None), "pubtime"),
            (entry(published="2026-09-19T19:00:00+00:00"), "pubtime"),
            (entry(version="2.0.0"), "missing"),
            (entry() + "\n" + entry(), "duplicate"),
            ('{"name":"sample","vers":"1.2.3","vers":"2.0.0"}', "duplicate"),
            ('{"name":"sample","vers":[]}', "malformed sparse-index version"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(gate.Refusal, reason):
                    gate.check_index("sample", {"1.2.3": CHECKSUM}, response, NOW)

    def test_seven_day_boundary_and_future_publication(self):
        at_boundary = entry(published="2026-09-20T19:00:00Z")
        self.assertEqual(gate.check_index("sample", {"1.2.3": CHECKSUM}, at_boundary, NOW), [])
        younger = entry(published="2026-09-20T19:00:01Z")
        self.assertEqual(gate.check_index("sample", {"1.2.3": CHECKSUM}, younger, NOW),
                         [("sample", "1.2.3", NOW + dt.timedelta(seconds=1))])
        future = entry(published="2026-09-28T19:00:00Z")
        self.assertEqual(len(gate.check_index("sample", {"1.2.3": CHECKSUM}, future, NOW)), 1)

    def test_full_locked_registry_graph_is_checked_without_fetching_crates(self):
        lock = '''version = 4
[[package]]
name = "sample"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "''' + CHECKSUM + '''"
[[package]]
name = "sample"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "''' + CHECKSUM + '''"
[[package]]
name = "local"
version = "0.1.0"
[[package]]
name = "git-package"
version = "0.1.0"
source = "git+https://github.com/example/repo?rev=0000000000000000000000000000000000000000#0000000000000000000000000000000000000000"
'''
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "Cargo.lock"
            path.write_text(lock)
            calls = []

            def fetch(name):
                calls.append(name)
                return "\n".join((entry(version="1.2.3"),
                                  entry(version="2.0.0", published="2026-09-26T19:00:00Z")))

            result = gate.preflight(path, fetch=fetch, now=NOW)
        self.assertEqual(calls, ["sample"])
        self.assertEqual(result["registry_package_count"], 2)
        self.assertEqual(result["local_packages_not_audited"], 1)
        self.assertEqual(result["git_packages_not_audited"], 1)
        self.assertFalse(result["registry_preflight_passed"])
        self.assertEqual(result["younger_than_hold"][0]["version"], "2.0.0")
        self.assertFalse(result["cargo_fetch_executed"])
        self.assertFalse(result["private_mode_approved"])

    def test_exact_exception_allows_only_reviewed_young_package(self):
        lock = ('version = 4\n[[package]]\nname = "sample"\nversion = "1.2.3"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                f'checksum = "{CHECKSUM}"\n')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock_path = root / "Cargo.lock"
            lock_path.write_text(lock)
            exception_path = root / "exception.json"
            manifest = {
                "schema_version": 1,
                "scope": gate.NU7_EXCEPTION_SCOPE,
                "cargo_lock_sha256": hashlib.sha256(lock.encode()).hexdigest(),
                "packages": [{"name": "sample", "version": "1.2.3",
                              "checksum": CHECKSUM}],
            }
            exception_path.write_text(json.dumps(manifest))
            digest = hashlib.sha256(exception_path.read_bytes()).hexdigest()

            def fetch(_):
                return entry(published="2026-09-26T19:00:00Z")

            ordinary = gate.preflight(lock_path, fetch=fetch, now=NOW)
            self.assertFalse(ordinary["registry_preflight_passed"])
            approved = gate.preflight(lock_path, fetch=fetch, now=NOW,
                                      exception_path=exception_path,
                                      exception_sha256=digest)
            self.assertTrue(approved["registry_preflight_passed"])
            self.assertEqual(approved["hold_exception_applied"],
                             [{"name": "sample", "version": "1.2.3"}])
            self.assertFalse(approved["approved_release"])
            with self.assertRaisesRegex(gate.Refusal, "digest differs"):
                gate.preflight(lock_path, fetch=fetch, now=NOW,
                               exception_path=exception_path,
                               exception_sha256="0" * 64)
            lock_path.write_text(lock + '[[package]]\nname = "local"\nversion = "0.1.0"\n')
            with self.assertRaisesRegex(gate.Refusal, "exact lockfile"):
                gate.preflight(lock_path, fetch=fetch, now=NOW,
                               exception_path=exception_path,
                               exception_sha256=digest)

    def test_exception_does_not_cover_new_young_version(self):
        lock = ('version = 4\n[[package]]\nname = "sample"\nversion = "1.2.3"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                f'checksum = "{CHECKSUM}"\n[[package]]\nname = "sample"\n'
                'version = "2.0.0"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                f'checksum = "{CHECKSUM}"\n')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock_path = root / "Cargo.lock"
            lock_path.write_text(lock)
            exception_path = root / "exception.json"
            exception_path.write_text(json.dumps({
                "schema_version": 1, "scope": gate.NU7_EXCEPTION_SCOPE,
                "cargo_lock_sha256": hashlib.sha256(lock.encode()).hexdigest(),
                "packages": [{"name": "sample", "version": "1.2.3",
                              "checksum": CHECKSUM}],
            }))
            digest = hashlib.sha256(exception_path.read_bytes()).hexdigest()
            result = gate.preflight(
                lock_path, now=NOW, exception_path=exception_path,
                exception_sha256=digest,
                fetch=lambda _: "\n".join((
                    entry(published="2026-09-26T19:00:00Z"),
                    entry(version="2.0.0", published="2026-09-26T19:00:00Z"))),
            )
            self.assertFalse(result["registry_preflight_passed"])
            self.assertEqual(len(result["hold_exception_applied"]), 1)

    def test_unknown_or_unpinned_sources_are_rejected(self):
        for source in ("registry+https://example.invalid/index",
                       "git+https://github.com/example/repo?branch=main"):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "Cargo.lock"
                path.write_text('version = 4\n[[package]]\nname = "example"\n'
                                'version = "1.0.0"\nsource = "' + source + '"\n')
                with self.assertRaisesRegex(gate.Refusal, "unknown or unpinned"):
                    gate.locked_packages(path)

    def test_missing_local_package_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "Cargo.lock"
            path.write_text('version = 4\n[[package]]\nname = "local"\n')
            with self.assertRaisesRegex(gate.Refusal, "missing Cargo.lock package identity"):
                gate.locked_packages(path)


if __name__ == "__main__":
    unittest.main()
