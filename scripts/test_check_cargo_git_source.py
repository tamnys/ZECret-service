"""Networkless negative tests for the reviewed Cargo Git-source gate."""

import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("check-cargo-git-source.py")
spec = importlib.util.spec_from_file_location("check_cargo_git_source", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def commit():
    return {"sha": gate.COMMIT, "tree": {"sha": gate.TREE}}


def run():
    return {"id": gate.RUN_ID, "head_sha": gate.COMMIT, "event": "push",
            "created_at": gate.RUN_CREATED, "conclusion": "success",
            "repository": {"id": gate.REPOSITORY_ID},
            "head_repository": {"id": gate.REPOSITORY_ID}}


def source_files(root, extra_lock="", manifest_replacement=None):
    locked = ['version = 4']
    for name, version in gate.PACKAGES.items():
        locked.append(f'[[package]]\nname = "{name}"\nversion = "{version}"\nsource = "{gate.LOCK_SOURCE}"')
    (root / "Cargo.lock").write_text("\n".join(locked) + "\n" + extra_lock)
    deps = "\n".join(f'{name} = {{ git = "{gate.GIT_URL}", rev = "{gate.COMMIT}", version = "={version}" }}'
                     for name, version in gate.PACKAGES.items())
    (root / "Cargo.toml").write_text("[workspace.dependencies]\n" +
                                      (manifest_replacement if manifest_replacement is not None else deps))


class GitSourceGateTests(unittest.TestCase):
    def test_valid_reviewed_source_checks_both_upstream_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_files(root)
            requests = []

            def fetch(path):
                requests.append(path)
                return commit() if path.startswith("git/") else run()

            result = gate.preflight(root, fetch=fetch,
                                    now=dt.datetime(2026, 9, 27, tzinfo=dt.timezone.utc))
        self.assertEqual(requests, [f"git/commits/{gate.COMMIT}",
                                    f"actions/runs/{gate.RUN_ID}"])
        self.assertTrue(result["git_source_metadata_preflight_passed"])
        self.assertFalse(result["git_object_fetched_or_checked_locally"])
        self.assertFalse(result["cargo_fetch_executed"])
        self.assertFalse(result["private_mode_approved"])

    def test_added_git_package_is_refused_before_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_files(root, '\n[[package]]\nname = "unreviewed"\nversion = "1.0.0"\n'
                               f'source = "{gate.LOCK_SOURCE}"\n')
            with self.assertRaisesRegex(gate.Refusal, "unreviewed or duplicate"):
                gate.preflight(root, fetch=lambda _: self.fail("network access before input check"))

    def test_changed_manifest_pin_is_refused_before_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_files(root, manifest_replacement='cc-eventlog = { git = "https://example.invalid/repo", '
                           f'rev = "{gate.COMMIT}", version = "=0.5.9" }}')
            with self.assertRaisesRegex(gate.Refusal, "workspace Git dependency differs"):
                gate.preflight(root, fetch=lambda _: self.fail("network access before input check"))

    def test_wrong_tree_or_push_run_is_refused(self):
        valid_now = dt.datetime(2026, 9, 27, tzinfo=dt.timezone.utc)
        for changed, field, reason in (
            ("commit", "sha", "Git commit"),
            ("tree", "sha", "Git commit"),
            ("run", "head_sha", "push-run"),
            ("run", "event", "push-run"),
            ("run", "created_at", "publication time"),
            ("repository", "id", "push-run"),
        ):
            with self.subTest(changed=changed, field=field):
                candidate_commit, candidate_run = commit(), run()
                if changed == "commit":
                    candidate_commit[field] = "0" * 40
                elif changed == "tree":
                    candidate_commit["tree"][field] = "0" * 40
                elif changed == "repository":
                    candidate_run["repository"][field] = 0
                else:
                    candidate_run[field] = "changed"
                with self.assertRaisesRegex(gate.Refusal, reason):
                    gate.check_upstream(candidate_commit, candidate_run, valid_now)

    def test_hold_uses_upstream_run_time_not_commit_timestamp(self):
        publication = dt.datetime(2026, 4, 21, 3, 58, 44, tzinfo=dt.timezone.utc)
        with self.assertRaisesRegex(gate.Refusal, "seven-day hold"):
            gate.check_upstream(commit(), run(), publication + gate.HOLD - dt.timedelta(seconds=1))
        gate.check_upstream(commit(), run(), publication + gate.HOLD)

    def test_duplicate_json_key_is_rejected(self):
        with self.assertRaisesRegex(gate.Refusal, "duplicate GitHub API JSON key"):
            gate.unique_json_object([("sha", gate.COMMIT), ("sha", "0" * 40)])

    def test_workflow_token_authenticates_only_reviewed_api_paths(self):
        class Response:
            status = 200
            url = gate.API + f"git/commits/{gate.COMMIT}"

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def read(self):
                return json.dumps(commit()).encode()

        opener = mock.Mock()
        opener.open.return_value = Response()
        with mock.patch.dict("os.environ", {"GITHUB_TOKEN": "synthetic-token"}), \
                mock.patch.object(gate.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(gate.github_json(f"git/commits/{gate.COMMIT}"), commit())
            with self.assertRaisesRegex(gate.Refusal, "unreviewed GitHub API path"):
                gate.github_json("git/commits/changed")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-token")
        self.assertEqual(request.full_url, Response.url)
        opener.open.assert_called_once()


if __name__ == "__main__":
    unittest.main()
