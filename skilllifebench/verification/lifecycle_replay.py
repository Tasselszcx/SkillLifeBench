#!/usr/bin/env python3
"""Recompute all 1,680 lifecycle outcomes from the public frozen snapshots.

Standard-library only. No inference, task implementation execution, or pickle
loading occurs. Original absolute paths are identifiers in the portable index;
they are never opened. The archived graders and replay routine are hash-pinned.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import types
from datetime import datetime, timezone


RELEASE_ROOT = Path(__file__).resolve().parents[2] / "data/lifecycle"
INDEX_SHA256 = "4f2c2240901d808e4edb5e5e0a9402b1eb91f4abc664406f00b89622746ee2fa"
REPLAY_SHA256 = "6021584e9349b903c634c0489238790a4bfc3ade33408dba4cb628b10dc2cc0b"
GRADER_SHA256 = {
    "effect_oracle.py": "df60c0304989f5b2dbe40c9b810c3a5aa72f24d12f5ea116419d7d49517a5291",
    "b_tasks.py": "6b7e4247db3ef6d352a0db352d3d52c378a343bdc6622561e261020d5137998c",
    "d_tasks.py": "e59b9d7fd1abbd35f4d55dc227fcac07ee3602be35913432afc383f4838d2783",
    "e_tasks.py": "d17646b74c34aed2fc64b56ce925dbe3f0d6f6a44e67c37c49af28576e6255b5",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def safe_path(root, relative):
    name = PurePosixPath(relative)
    require(bool(name.parts) and not name.is_absolute() and ".." not in name.parts,
            "Unsafe public evidence path")
    root = Path(root).resolve()
    path = root.joinpath(*name.parts)
    require(path.resolve().is_relative_to(root), "Evidence path escapes extraction directory")
    require(not path.is_symlink(), "Evidence must be a regular file, not a symlink")
    return path


class Parts(io.RawIOBase):
    """Read split compressed evidence without creating another archive copy."""

    def __init__(self, paths):
        self.paths = iter(paths)
        self.current = None

    def readable(self):
        return True

    def read(self, size=-1):
        size = 1024 * 1024 if size < 0 else size
        result = bytearray()
        while len(result) < size:
            if self.current is None:
                try:
                    self.current = next(self.paths).open("rb")
                except StopIteration:
                    break
            block = self.current.read(size - len(result))
            if block:
                result.extend(block)
            else:
                self.current.close()
                self.current = None
        return bytes(result)

    def close(self):
        if self.current is not None:
            self.current.close()
        super().close()


def extract_evidence(release_root, destination):
    """Verify split archive hashes, then extract regular members into a new root."""
    archive_root = Path(release_root) / "evidence"
    meta = read_json(archive_root / "archive-index.json")
    require(meta["portable_index_sha256"] == INDEX_SHA256, "Not the frozen v60 evidence index")
    destination = Path(destination)
    require(not destination.exists() or not any(destination.iterdir()),
            "Extraction directory must be absent or empty")
    destination.mkdir(parents=True, exist_ok=True)
    parts, combined = [], hashlib.sha256()
    for part in meta["parts"]:
        path = safe_path(archive_root, part["name"])
        require(path.stat().st_size == part["bytes"] and digest(path) == part["sha256"],
                "Compressed evidence part hash differs")
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                combined.update(block)
        parts.append(path)
    require(combined.hexdigest() == meta["concatenated_sha256"], "Combined archive hash differs")
    observed = set()
    with Parts(parts) as pieces, lzma.LZMAFile(pieces, "rb") as stream:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            for member in archive:
                require(member.isfile(), "Archive contains a nonregular member")
                require(member.name not in observed, "Duplicate archive member")
                observed.add(member.name)
                path = safe_path(destination, member.name)
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, path.open("xb") as target:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        target.write(block)
                require(path.stat().st_size == member.size, "Truncated archive member")
    return meta


def verify_header_derivative(row, raw):
    """Check the public interval proof without claiming to recover private bytes."""
    transformation = row["transformation"]
    require(transformation.get("all_other_bytes_exact") is True
            and transformation.get("redactions"), "Missing header derivative proof")
    content = json.loads(raw)
    segments = []
    for interval in transformation["unchanged_byte_intervals"]:
        p0, p1 = interval["public_start"], interval["public_end"]
        o0, o1 = interval["original_start"], interval["original_end"]
        require(0 <= p0 <= p1 <= len(raw) and 0 <= o0 <= o1 <= row["original_bytes"]
                and p1 - p0 == o1 - o0, "Invalid unchanged byte interval")
        require(hashlib.sha256(raw[p0:p1]).hexdigest() == interval["sha256"],
                "Public unchanged-byte interval hash differs")
        segments.append((p0, p1, o0, o1))
    for redaction in transformation["redactions"]:
        pointer = redaction["json_pointer"]
        require(re.fullmatch(r"/response_headers/\d+/1", pointer), "Nonheader evidence was redacted")
        header_index = int(pointer.split("/")[2])
        require(content["response_headers"][header_index] == [redaction["header_name"], None],
                "Redacted header is not null")
        public, original = redaction["public_json_token"], redaction["original_json_token"]
        p0, p1 = public["start_byte"], public["end_byte"]
        o0, o1 = original["start_byte"], original["end_byte"]
        require(0 <= p0 < p1 <= len(raw) and 0 <= o0 < o1 <= row["original_bytes"]
                and raw[p0:p1] == b"null" and public["literal"] == "null",
                "Invalid public redaction token")
        segments.append((p0, p1, o0, o1))
    previous_public = previous_original = 0
    for p0, p1, o0, o1 in sorted(segments):
        require(p0 == previous_public and o0 == previous_original,
                "Derivative proof contains a gap, overlap, or reordered bytes")
        previous_public, previous_original = p1, o1
    require(previous_public == len(raw) and previous_original == row["original_bytes"],
            "Derivative proof does not cover the complete document")


class PortableEvidence:
    """Resolve original (path, hash) bindings only through verified public bytes."""

    def __init__(self, root, index_sha256=INDEX_SHA256):
        self.root = Path(root).resolve()
        index = safe_path(self.root, "release/portable-path-index.jsonl")
        require(digest(index) == index_sha256, "Portable evidence index hash differs")
        self.rows = [json.loads(line) for line in index.read_text(encoding="utf-8").splitlines()]
        self.aliases, self.public = {}, {}
        self.derivatives = 0
        for row in self.rows:
            path = safe_path(self.root, row["public_path"])
            require(path.stat().st_size == row["public_bytes"] and digest(path) == row["public_sha256"],
                    "Public evidence size or hash differs: " + row["public_path"])
            require(row["public_path"] not in self.public, "Duplicate portable public path")
            self.public[row["public_path"]] = row
            if row["byte_identical"]:
                require(row["original_sha256"] == row["public_sha256"]
                        and row["original_bytes"] == row["public_bytes"], "False byte-identity claim")
            else:
                verify_header_derivative(row, path.read_bytes())
                self.derivatives += 1
            for original in row["original_paths"]:
                key = (original, row["original_sha256"])
                require(key not in self.aliases or self.aliases[key]["public_sha256"] == row["public_sha256"],
                        "Conflicting original path/hash binding")
                self.aliases[key] = row

    def resolve(self, original_path, original_sha256, *, require_identical=False):
        row = self.aliases.get((str(original_path), original_sha256))
        require(row is not None, "Original path/hash binding is absent from public evidence")
        require(not require_identical or row["byte_identical"],
                "Replay input must retain exact original bytes")
        return safe_path(self.root, row["public_path"])

    def member(self, relative):
        require(relative in self.public, "Requested member is outside verified evidence")
        return safe_path(self.root, relative)

    def source(self, filename, expected_hash):
        choices = [row for row in self.rows if row["original_sha256"] == expected_hash
                   and any(PurePosixPath(path).name == filename for path in row["original_paths"])]
        require(bool(choices), "Frozen source is missing: " + filename)
        row = choices[0]
        return self.resolve(row["original_paths"][0], expected_hash, require_identical=True)


def load_exact_module(name, path, expected_hash):
    """Import the hash-checked Python bytes, ignoring any mutable pycache files."""
    raw = Path(path).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected_hash, "Pinned Python source hash differs")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def load_frozen_replay(evidence):
    path = evidence.source("offline_regrade.py", REPLAY_SHA256)
    return load_exact_module("_skilllifebench_frozen_snapshot_replay", path, REPLAY_SHA256)


def load_graders(frozen, plan, relocated):
    """Supply public locations to the original class; its grading methods are unchanged."""
    namespace = "_slb_public_snapshot_replay_" + frozen.object_sha(plan)[:12]
    for name in (namespace, namespace + ".lifecycle"):
        package = types.ModuleType(name)
        package.__path__ = []
        sys.modules[name] = package
    graders = frozen.FrozenGraders.__new__(frozen.FrozenGraders)
    graders.bindings, graders.modules = [], {}
    for filename, module_name in (("effect_oracle.py", "effect_oracle"),
                                  ("b_tasks.py", "lifecycle.b_tasks"),
                                  ("d_tasks.py", "lifecycle.d_tasks"),
                                  ("e_tasks.py", "lifecycle.e_tasks")):
        original = next(path for path in relocated if Path(path).name == filename)
        path = Path(relocated[original]["snapshot"])
        graders.modules[filename] = load_exact_module(namespace + "." + module_name, path, GRADER_SHA256[filename])
        graders.bindings.append({"original_path": original, "path": str(path), "sha256": digest(path)})
    graders.captured_bytes = graders.modules["effect_oracle.py"].captured_bytes
    return graders


def run(output, evidence_root=None, release_root=RELEASE_ROOT):
    """Replay every final slot and write per-episode checks plus an aggregate report."""
    output = Path(output).resolve()
    require(not output.exists(), "Use a new replay output directory")
    output.mkdir(parents=True)
    evidence_root = Path(evidence_root).resolve() if evidence_root else output / "evidence"
    if not (evidence_root / "release/portable-path-index.jsonl").is_file():
        extract_evidence(release_root, evidence_root)
    evidence = PortableEvidence(evidence_root)
    frozen = load_frozen_replay(evidence)
    plan_path = evidence.member("inputs/plan.json")
    plan = read_json(plan_path)
    selected_path = evidence.member("analysis/selected-outcome-index.json")
    selected = read_json(selected_path)
    verification = read_json(evidence.member("analysis/verification.json"))
    require(verification["plan"]["sha256"] == digest(plan_path)
            and verification["complete"] is True and verification["valid"] == 1680,
            "Final analysis is not bound to the complete execution plan")
    require(plan["task_count"] == 60 and plan["template_count"] == 12 and len(plan["models"]) == 14,
            "Unexpected final population")
    manifest = plan["task_manifest"]
    task_path = evidence.resolve(manifest["path"], manifest["sha256"], require_identical=True)
    tasks = {task["id"]: task for task in read_json(task_path)["tasks"]}
    require(len(tasks) == 60 and set(tasks) == set(plan["task_ids"]), "Frozen task population differs")
    scheduled = {f"{model['key']}/{task}/{condition}" for model in plan["models"]
                 for task in plan["task_ids"] for condition in plan["conditions"]}
    require(len(selected) == len(scheduled) == 1680
            and {row["job_id"] for row in selected} == scheduled, "Final selected slots are incomplete")

    # Only local source locations change; the exact source hashes and grader code do not.
    source_manifest = read_json(evidence.member("source-freeze/01/source-manifest.json"))
    relocated = {}
    for filename, expected_hash in GRADER_SHA256.items():
        sources = [item for item in plan["implementation_bindings"] if Path(item["path"]).name == filename]
        require(len(sources) == 1 and sources[0]["sha256"] == expected_hash, "Frozen grader hash differs")
        original = sources[0]["path"]
        item = source_manifest[original]
        require(item["sha256"] == expected_hash, "Archived source-manifest binding differs")
        local = evidence.resolve(item["snapshot"], expected_hash, require_identical=True)
        relocated[original] = {**item, "snapshot": str(local)}
    source_directory = output / "resolved-source-manifest"
    source_directory.mkdir()
    write_json(source_directory / "source-manifest.json", relocated)
    graders = load_graders(frozen, plan, relocated)
    episodes = output / "episodes"
    episodes.mkdir()
    rows, failures = [], []
    for index, original in enumerate(selected):
        try:
            path = evidence.resolve(original["outcome_path"], original["outcome_sha256"], require_identical=True)
            row = {**original, "outcome_path": str(path)}
            result = frozen.regrade_episode(row, tasks[row["task_id"]], plan, graders)
            rows.append(result)
            write_json(episodes / f"episode-{index:04d}.json", result)
        except Exception as error:
            failures.append({"job_id": original["job_id"], "type": type(error).__name__, "error": str(error)})
    totals = {}
    for row in rows:
        cell = totals.setdefault(row["model_key"], {}).setdefault(row["condition"],
            {"N": 0, "task_success": 0, "harm": 0, "joint_success": 0})
        cell["N"] += 1
        for key in ("task_success", "harm", "joint_success"):
            cell[key] += int(row[key])
    coverage = read_json(evidence.member("analysis/coverage.json"))
    aggregates_match = not failures and all(
        totals[cell["model"]][cell["condition"]] == {"N": cell["valid"], **{
            key: cell[key] for key in ("task_success", "harm", "joint_success")}}
        for cell in coverage["cells"])
    report = {
        "schema": "skilllifebench-portable-lifecycle-replay/v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "complete": len(rows) == 1680 and not failures and aggregates_match,
        "planned": 1680, "matched": len(rows), "aggregate_counts_match": aggregates_match,
        "model_calls": 0, "skill_implementations_executed": 0, "pickle_objects_loaded": 0,
        "verdict_criteria_changed": False, "stored_records_modified": False,
        "evidence_files_verified": len(evidence.rows),
        "header_derivative_files_verified": evidence.derivatives,
        "header_derivative_scope": "Public null tokens and all unchanged-byte interval hashes are verified; private header values are neither reconstructed nor needed by the graders.",
        "replay_inputs_byte_identical": True, "portable_index_sha256": INDEX_SHA256,
        "frozen_replay_sha256": REPLAY_SHA256, "frozen_grader_sources": graders.bindings,
        "plan_sha256": digest(plan_path), "selected_index_sha256": digest(selected_path),
        "prefixes_regraded": sum(row["prefix_count"] for row in rows),
        "captured_file_records_verified": sum(row["captured_file_records_verified"] for row in rows),
        "declared_source_writes_replayed": sum(row["declared_source_writes_replayed"] for row in rows),
        "models": totals, "failures": failures,
        "method": "Exact archived pure graders recompute initial, per-action and final snapshot predicates. Attack-goal success is retained across execution prefixes. Stored Boolean scores serve only as comparison targets.",
    }
    compact = [{key: value for key, value in row.items() if key not in {"evidence", "replayed_prefixes", "outcome"}}
               for row in rows]
    if compact:
        with (output / "episode-comparison.csv").open("x", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(compact[0]))
            writer.writeheader()
            writer.writerows(compact)
    write_json(output / "replay-report.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="New directory for replay reports")
    parser.add_argument("--evidence-root", type=Path,
                        help="Extract/reuse public evidence here (default: OUTPUT/evidence, about 620 MB)")
    parser.add_argument("--release-root", type=Path, default=RELEASE_ROOT,
                        help="Frozen lifecycle release directory")
    args = parser.parse_args(argv)
    try:
        report = run(args.output, args.evidence_root, args.release_root)
    except (ValueError, OSError, KeyError) as error:
        print(f"Lifecycle replay failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({key: report[key] for key in (
        "complete", "matched", "aggregate_counts_match", "prefixes_regraded", "model_calls")}, indent=2))
    return 0 if report["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
