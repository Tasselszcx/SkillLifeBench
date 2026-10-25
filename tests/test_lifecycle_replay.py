"""Integrity regression tests for the portable frozen-evidence resolver."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest


from skilllifebench.verification import lifecycle_replay as replay


class PortableEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

    def make_index(self, rows):
        path = self.root / "release/portable-path-index.jsonl"
        path.parent.mkdir(exist_ok=True)
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        return replay.digest(path)

    def plain(self, content=b'{"task_success": true}'):
        path = self.root / "outcome.json"
        path.write_bytes(content)
        sha = hashlib.sha256(content).hexdigest()
        return {"original_paths": ["/nonexistent/private/outcome.json"],
                "original_sha256": sha, "public_sha256": sha,
                "original_bytes": len(content), "public_bytes": len(content),
                "byte_identical": True, "public_path": "outcome.json"}

    def derivative(self):
        raw = b'{"response_headers": [["Set-Cookie", null]], "score": true}'
        path = self.root / "header.json"
        path.write_bytes(raw)
        start = raw.index(b"null")
        end = start + 4
        original_end = start + 12
        row = {"original_paths": ["/unavailable/private/header.json"],
               "original_sha256": "a" * 64, "public_sha256": replay.digest(path),
               "original_bytes": len(raw) + 8, "public_bytes": len(raw),
               "byte_identical": False, "public_path": "header.json",
               "transformation": {"all_other_bytes_exact": True,
                   "redactions": [{"header_name": "Set-Cookie", "json_pointer": "/response_headers/0/1",
                       "public_json_token": {"start_byte": start, "end_byte": end, "literal": "null"},
                       "original_json_token": {"start_byte": start, "end_byte": original_end}}],
                   "unchanged_byte_intervals": [
                       {"public_start": 0, "public_end": start, "original_start": 0, "original_end": start,
                        "sha256": hashlib.sha256(raw[:start]).hexdigest()},
                       {"public_start": end, "public_end": len(raw), "original_start": original_end,
                        "original_end": len(raw) + 8, "sha256": hashlib.sha256(raw[end:]).hexdigest()}]}}
        return row

    def test_original_path_is_identifier_only(self):
        row = self.plain()
        evidence = replay.PortableEvidence(self.root, self.make_index([row]))
        self.assertEqual(evidence.resolve(row["original_paths"][0], row["original_sha256"],
                                         require_identical=True), self.root / "outcome.json")
        with self.assertRaisesRegex(ValueError, "absent"):
            evidence.resolve(row["original_paths"][0], "b" * 64)

    def test_tampered_public_outcome_rejected(self):
        row = self.plain()
        index_sha = self.make_index([row])
        (self.root / "outcome.json").write_bytes(b'{"task_success":false}')
        with self.assertRaisesRegex(ValueError, "hash differs"):
            replay.PortableEvidence(self.root, index_sha)

    def test_header_derivative_keeps_distinct_original_hash(self):
        row = self.derivative()
        evidence = replay.PortableEvidence(self.root, self.make_index([row]))
        self.assertEqual(evidence.derivatives, 1)
        self.assertEqual(evidence.resolve(row["original_paths"][0], row["original_sha256"]),
                         self.root / "header.json")
        with self.assertRaisesRegex(ValueError, "exact original bytes"):
            evidence.resolve(row["original_paths"][0], row["original_sha256"], require_identical=True)

    def test_nonheader_derivative_rejected(self):
        row = self.derivative()
        row["transformation"]["redactions"][0]["json_pointer"] = "/score"
        with self.assertRaisesRegex(ValueError, "Nonheader"):
            replay.PortableEvidence(self.root, self.make_index([row]))

    def test_derivative_proof_gap_rejected(self):
        row = self.derivative()
        row["transformation"]["unchanged_byte_intervals"].pop()
        with self.assertRaisesRegex(ValueError, "complete document"):
            replay.PortableEvidence(self.root, self.make_index([row]))

    def test_unsafe_paths_rejected(self):
        for path in ("../escape", "/tmp/outside"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                replay.safe_path(self.root, path)
        (self.root / "linked").symlink_to("/tmp")
        with self.assertRaises(ValueError):
            replay.safe_path(self.root, "linked/outside")

    def test_missing_frozen_source_rejected(self):
        row = self.plain()
        evidence = replay.PortableEvidence(self.root, self.make_index([row]))
        with self.assertRaisesRegex(ValueError, "source is missing"):
            replay.load_frozen_replay(evidence)

    def test_modified_source_cannot_execute(self):
        path = self.root / "source.py"
        path.write_text("raise RuntimeError('should not execute')\n")
        with self.assertRaisesRegex(ValueError, "source hash differs"):
            replay.load_exact_module("_bad_frozen_source", path, "0" * 64)


if __name__ == "__main__":
    unittest.main()
