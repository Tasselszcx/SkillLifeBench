"""Integrity and denominator regressions for the public release check."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "scripts/verify_release.py"
SPEC = importlib.util.spec_from_file_location("release_verify_tested", SOURCE)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def seal(root):
    files = [{"path": relative, "bytes": (root / relative).stat().st_size,
              "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest()}
             for relative in VERIFY.iter_release_paths(root)]
    (root / "release-manifest.json").write_text(json.dumps({"files": files}))


class ManifestTests(unittest.TestCase):
    def test_local_configuration_is_ignored_without_reading_it(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "data.json").write_text("data")
            (root / ".env.example").write_text("EXAMPLE=placeholder")
            seal(root)
            local_names = (".env", ".env.local", "credentials-user.json", "private.pem", "private.key",
                           "runs/session.json", "outputs/local.json", "local-results/run.json", ".cache/item.json")
            blocked = set()
            for relative in local_names:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("local private configuration must not be read")
                blocked.add(path)
            original_open = Path.open
            def guarded_open(path, *args, **kwargs):
                if path in blocked:
                    raise AssertionError("Local private file was read")
                return original_open(path, *args, **kwargs)
            with patch.object(Path, "open", guarded_open):
                self.assertEqual(VERIFY.verify_manifest(root)["files"], 2)

    def test_manifest_checks_bytes_and_ignores_only_generated_caches(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "data.json").write_text("original")
            (root / "__pycache__").mkdir()
            (root / "__pycache__/cache.pyc").write_bytes(b"not part of release")
            seal(root)
            self.assertEqual(VERIFY.verify_manifest(root)["files"], 1)
            (root / "data.json").write_text("modified")
            with self.assertRaisesRegex(VERIFY.VerificationError, "digest mismatch"):
                VERIFY.verify_manifest(root)

    def test_unlisted_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "data.json").write_text("data")
            seal(root)
            (root / "extra.json").write_text("extra")
            with self.assertRaisesRegex(VERIFY.VerificationError, "unlisted"):
                VERIFY.verify_manifest(root)

    def test_unsafe_manifest_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for relative in ("../secret", "/absolute", "."):
                (root / "release-manifest.json").write_text(json.dumps({"files": [{"path": relative}]}))
                with self.assertRaisesRegex(VERIFY.VerificationError, "Unsafe"):
                    VERIFY.verify_manifest(root)

    def test_symlink_is_not_accepted_as_a_sealed_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "data.json").write_text("data")
            seal(root)
            (root / "data.json").unlink()
            (root / "data.json").symlink_to("/dev/null")
            with self.assertRaisesRegex(VERIFY.VerificationError, "symlink"):
                VERIFY.verify_manifest(root)

    def test_missing_manifest_returns_nonzero_and_failed_report(self):
        with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as scratch, \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            output = Path(scratch) / "check"
            code = VERIFY.main(["--root", repo, "--output", str(output)])
            report = json.loads((output / "verification-report.json").read_text())
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "failed")
        self.assertIn("Missing release-manifest.json", report["error"])

    def test_nonempty_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as scratch:
            output = Path(scratch)
            original = output / "keep.txt"
            original.write_text("unchanged")
            with self.assertRaisesRegex(VERIFY.VerificationError, "new or empty"):
                VERIFY.prepare_output(Path(repo), output)
            self.assertEqual(original.read_text(), "unchanged")


class DecisionTests(unittest.TestCase):
    def setUp(self):
        self.rows = [{"model": model, "case_id": case, "condition": condition,
                      "task_success": True, "goal_success": False, "joint_success": True}
                     for model in ("m1", "m2") for case in ("c1", "c2") for condition in ("clean", "attack")]

    def tally(self, rows):
        return VERIFY.tally_records(rows, {"m1", "m2"}, {"c1", "c2"}, ("clean", "attack"))

    def test_exact_cartesian_product_required(self):
        self.assertEqual(self.tally(self.rows)[("m1", "attack")]["joint"], 2)
        with self.assertRaisesRegex(VERIFY.VerificationError, "Missing"):
            self.tally(self.rows[:-1])
        with self.assertRaisesRegex(VERIFY.VerificationError, "Duplicate"):
            self.tally(self.rows[:-1] + [self.rows[0]])

    def test_integer_and_missing_values_are_not_boolean_scores(self):
        for value in (1, 0, None, "False"):
            rows = copy.deepcopy(self.rows)
            rows[0]["task_success"] = value
            with self.assertRaisesRegex(VERIFY.VerificationError, "Non-Boolean"):
                self.tally(rows)
        for value in ("", "unresolved", "1", "true"):
            with self.assertRaises(VERIFY.VerificationError):
                VERIFY.bool_csv(value)

    def test_joint_success_must_mean_completed_task_without_goal(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["goal_success"] = True
        with self.assertRaisesRegex(VERIFY.VerificationError, "predicate mismatch"):
            self.tally(rows)

    def test_full_replay_cannot_pass_on_zero_exit_with_incomplete_report(self):
        with tempfile.TemporaryDirectory() as folder, redirect_stdout(io.StringIO()):
            output = Path(folder)
            (output / "hosted-verification.json").write_text(json.dumps({"boolean_records": 2136}))
            (output / "qwen-verification.json").write_text(json.dumps({"status": "passed", "episodes": 534,
                "baseline_episodes": 356, "same_record_default_check_pairs": 178, "scorer_reproduction": True}))
            (output / "lifecycle-replay").mkdir()
            (output / "lifecycle-replay/replay-report.json").write_text(json.dumps({"complete": False,
                "planned": 1680, "matched": 1679, "aggregate_counts_match": False, "failures": ["one row"]}))
            with patch.object(VERIFY.subprocess, "run", return_value=SimpleNamespace(returncode=0)):
                with self.assertRaisesRegex(VERIFY.VerificationError, "incomplete"):
                    VERIFY.run_full(output, output)


if __name__ == "__main__":
    unittest.main()
