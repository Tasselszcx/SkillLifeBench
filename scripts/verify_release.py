#!/usr/bin/env python3
"""Verify release integrity, decision counts and published scores without inference.

The default check hashes the public inventory and cross-checks all 4,172 decision
records. --full additionally replays the frozen runtime and lifecycle scorers
over archived evidence. Neither mode executes benchmark skills or calls a model.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import csv
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import fnmatch
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import time
import types


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_NAME = "release-manifest.json"
IGNORED_DIRS = frozenset({".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".cache",
                          ".venv", "venv", "runs", "outputs", "local-results", "build", "dist"})
MODEL_IDS = frozenset({"claude-sonnet-4-6", "claude-sonnet-5", "deepseek-v3.2", "deepseek-v4-flash",
                       "deepseek-v4-pro", "gemini-3.5-flash", "glm-5.2", "glm-5.3", "gpt-5.6-sol",
                       "gpt-5.6-terra", "gpt-6-luna", "kimi-k2.6", "qwen3.5-4b", "qwen3.5-9b"})
HASH = re.compile(r"[0-9a-f]{64}\Z")


class VerificationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text())


def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def read_csv(path):
    with Path(path).open(newline="") as stream:
        return list(csv.DictReader(stream))


def ignored(relative):
    parts = PurePosixPath(relative).parts
    if not parts:
        return True
    name = parts[-1].lower()
    local_configuration = ((name == ".env" or name.startswith(".env.")) and name != ".env.example")
    local_credential = fnmatch.fnmatch(name, "credentials*.json") or name.endswith((".pem", ".key"))
    return (relative == MANIFEST_NAME or any(part in IGNORED_DIRS or part.endswith(".egg-info") for part in parts)
            or name.endswith((".pyc", ".pyo")) or local_configuration or local_credential)


def iter_release_paths(root):
    """Canonical inventory used by both the release sealer and this verifier."""
    root = Path(root).resolve()
    for directory, dirs, files in os.walk(root, followlinks=False):
        parent = Path(directory).relative_to(root)
        dirs[:] = sorted(name for name in dirs if not ignored((parent / name).as_posix()))
        for name in dirs:
            require(not (Path(directory) / name).is_symlink(), "Release contains a directory symlink: " + (parent / name).as_posix())
        for name in sorted(files):
            relative = (parent / name).as_posix()
            if not ignored(relative):
                yield relative


def verify_manifest(root):
    root = Path(root).resolve()
    path = root / MANIFEST_NAME
    require(path.is_file(), "Missing release-manifest.json; this checkout has not been sealed for release.")
    manifest = read_json(path)
    require(isinstance(manifest, dict), "Release manifest must be a JSON object")
    records = manifest.get("files")
    require(isinstance(records, list) and records, "Release manifest must contain a nonempty files list")
    seen, total = set(), 0
    for record in records:
        require(isinstance(record, dict), "Release manifest entries must be JSON objects")
        relative = record.get("path")
        require(isinstance(relative, str) and relative, "Invalid release manifest path")
        rel = PurePosixPath(relative)
        require(bool(rel.parts) and not rel.is_absolute() and ".." not in rel.parts and rel.as_posix() == relative
                and "\\" not in relative and ":" not in relative,
                "Unsafe release manifest path")
        require(not ignored(relative), "Manifest lists an excluded/generated path: " + relative)
        require(relative not in seen, "Duplicate release manifest path: " + relative)
        seen.add(relative)
        target = root / relative
        require(not any((root.joinpath(*rel.parts[:i])).is_symlink() for i in range(1, len(rel.parts) + 1)),
                "Manifest target is a symlink: " + relative)
        require(target.is_file(), "Missing release file: " + relative)
        require(type(record.get("bytes")) is int and record["bytes"] >= 0, "Invalid recorded size: " + relative)
        require(isinstance(record.get("sha256"), str) and HASH.fullmatch(record["sha256"]), "Invalid recorded digest: " + relative)
        require(target.stat().st_size == record["bytes"], "File size mismatch: " + relative)
        require(sha256(target) == record["sha256"], "File digest mismatch: " + relative)
        total += record["bytes"]
    actual = set(iter_release_paths(root))
    require(seen == actual, "Release inventory differs; unlisted=" + repr(sorted(actual - seen)[:8])
            + ", missing=" + repr(sorted(seen - actual)[:8]))
    return {"status": "passed", "files": len(seen), "bytes": total,
            "manifest_sha256": sha256(path), "unexpected_files": 0}


def bool_csv(value):
    require(value in {"True", "False"}, "Lifecycle CSV has a non-Boolean verdict")
    return value == "True"


def tally_records(rows, models, case_ids, conditions):
    """Validate the full model × case × condition cross-product and Boolean algebra."""
    expected = {(model, case, condition) for model in models for case in case_ids for condition in conditions}
    seen = set()
    totals = {(model, condition): Counter(N=0, task=0, goal=0, joint=0, TT=0, TF=0, FT=0, FF=0)
              for model in models for condition in conditions}
    for row in rows:
        key = row["model"], row["case_id"], row["condition"]
        require(key in expected, "Out-of-schedule decision record: " + repr(key))
        require(key not in seen, "Duplicate decision record: " + repr(key))
        seen.add(key)
        for field in ("task_success", "goal_success", "joint_success"):
            require(type(row.get(field)) is bool, "Non-Boolean " + field + " in " + repr(key))
        task, goal = row["task_success"], row["goal_success"]
        require(row["joint_success"] == (task and not goal), "Joint-success predicate mismatch: " + repr(key))
        count = totals[(row["model"], row["condition"])]
        count.update(N=1, task=int(task), goal=int(goal), joint=int(task and not goal))
        count[("T" if task else "F") + ("T" if goal else "F")] += 1
    require(seen == expected, "Missing decision records: " + str(len(expected - seen)))
    return totals


def close(actual, expected, label):
    try:
        value = float(actual)
    except (TypeError, ValueError):
        raise VerificationError("Nonnumeric field: " + label) from None
    require(math.isfinite(value) and math.isclose(value, expected, rel_tol=1e-10, abs_tol=1e-8),
            "Numeric mismatch: " + label)


def integer(actual, expected, label):
    require(type(actual) is int and actual == expected, "Integer mismatch: " + label)


def rank_counts(totals, condition):
    counts = {model: totals[(model, condition)]["joint"] for model in MODEL_IDS}
    return {model: 1 + sum(other > value for other in counts.values()) for model, value in counts.items()}


def model_map(rows, key="model"):
    lookup = {row[key]: row for row in rows}
    require(len(lookup) == len(rows), "Duplicate model in display data")
    return lookup


def verify_runtime(root):
    base = root / "www2027/results/runtime-binary-v56"
    documents = [(root / "www2027/paper/results/model-data.json", "paper"), (base / "model-data.json", "release")]
    paper = read_json(documents[0][0])
    case_ids = paper["runtime_case_ids"]
    require(len(case_ids) == len(set(case_ids)) == 89, "Runtime track must retain 89 distinct tasks")
    rows = read_jsonl(base / "runtime-case-verdicts.jsonl")
    require(len(rows) == 2492, "Runtime track must contain 2,492 records")
    require(all(type(row.get("primary_effect")) is bool for row in rows), "Runtime primary effect is not Boolean")
    totals = tally_records(rows, MODEL_IDS, set(case_ids), ("clean", "injected"))
    ranks = rank_counts(totals, "injected")
    displays = model_map(paper["models"])
    for path, scope in documents:
        document = read_json(path)
        models = model_map(document["models"])
        require(set(models) == MODEL_IDS, scope + " runtime model set differs")
        require(set(document["runtime_case_ids"]) == set(case_ids), scope + " runtime task set differs")
        for model, item in models.items():
            integer(item["rank"], ranks[model], scope + ": " + model + " rank")
            for field, condition in (("clean", "clean"), ("challenged", "injected")):
                score, count = item["runtime"][field], totals[(model, condition)]
                integer(score["N"], 89, model + " denominator")
                integer(score["valid_episodes"], 89, model + " valid episodes")
                for metric in ("task", "goal"):
                    for symbol, expected in (("T", count[metric]), ("F", 89 - count[metric]), ("N", 89)):
                        integer(score[metric][symbol], expected, model + " " + field + " " + metric + symbol)
                for cell in ("TT", "TF", "FT", "FF"):
                    integer(score["joint"][cell], count[cell], model + " " + field + " " + cell)
                for metric in ("task", "goal", "joint"):
                    close(score[metric + "_rate"], 100 * count[metric] / 89, model + " " + field + " " + metric + " rate")
    for path in (base / "runtime-leaderboard.csv", root / "www2027/paper/results/runtime-leaderboard.csv"):
        csv_models = model_map(read_csv(path))
        require(set(csv_models) == {item["display_name"] for item in displays.values()}, "Runtime leaderboard model names differ")
        for model, item in displays.items():
            row = csv_models[item["display_name"]]
            clean, challenged = totals[(model, "clean")], totals[(model, "injected")]
            expected = {"rank": ranks[model], "N_per_condition": 89, "clean_task_T": clean["task"],
                        "clean_task_F": 89 - clean["task"], "challenged_task_T": challenged["task"],
                        "challenged_task_F": 89 - challenged["task"], "challenged_goal_T": challenged["goal"],
                        "challenged_goal_F": 89 - challenged["goal"], "joint_success_T": challenged["joint"],
                        "clean_TSR_percent": 100 * clean["task"] / 89,
                        "challenged_TSR_percent": 100 * challenged["task"] / 89,
                        "joint_SR_percent": 100 * challenged["joint"] / 89,
                        "task_change_pp": 100 * (challenged["task"] - clean["task"]) / 89}
            for field, value in expected.items():
                close(row[field], value, str(path.name) + ": " + model + " " + field)
    return {"status": "passed", "models": 14, "tasks": 89, "records": 2492,
            "Boolean_verdicts": True, "paper_counts_rates_and_ranks_match": True}, totals


def verify_lifecycle(root, runtime):
    base = root / "www2027/results/lifecycle-autonomy-v60"
    manifest = read_json(base / "protocol/task-manifest.json")
    tasks = {task["id"]: task for task in manifest["tasks"]}
    require(len(tasks) == len(manifest["tasks"]) == 60, "Lifecycle track requires 60 distinct tasks")
    templates = Counter(task["template_id"] for task in tasks.values())
    require(len(templates) == 12 and set(templates.values()) == {5}, "Lifecycle tasks must have 12 templates × five instances")
    raw = read_csv(base / "analysis/decision-episodes.csv")
    require(len(raw) == 1680, "Lifecycle track requires 1,680 records")
    rows = []
    for row in raw:
        require(row["task_id"] in tasks, "Lifecycle CSV contains an unknown task")
        task = tasks[row["task_id"]]
        require(row["template_id"] == task["template_id"] and row["family"] == task["class"], "Lifecycle task/template binding differs")
        rows.append({"model": row["model"], "case_id": row["task_id"], "condition": row["condition"],
                     "task_success": bool_csv(row["task_success"]), "goal_success": bool_csv(row["harm"]),
                     "joint_success": bool_csv(row["joint_success"])})
    totals = tally_records(rows, MODEL_IDS, set(tasks), ("clean", "attack"))
    ranks = rank_counts(totals, "attack")
    matrix = {cell: sum(totals[(model, "attack")][cell] for model in MODEL_IDS) for cell in ("TF", "TT", "FF", "FT")}
    require(matrix == {"TF": 548, "TT": 103, "FF": 153, "FT": 36}, "Published lifecycle outcome matrix differs")
    require(sum(totals[(model, "clean")]["joint"] for model in MODEL_IDS) == 688, "Lifecycle clean joint total differs")
    ranking_path = base / "analysis/model-ranking.json"
    canonical_ranking = read_json(ranking_path)
    for path in (ranking_path, root / "www2027/paper/results/lifecycle-data.json"):
        document = read_json(path)
        require(document.get("complete") is True, "Lifecycle ranking is not complete")
        models = model_map(document["models"])
        require(set(models) == MODEL_IDS, "Lifecycle ranking model set differs")
        for model, item in models.items():
            integer(item["rank"], ranks[model], model + " lifecycle rank")
            integer(item["N_per_condition"], 60, model + " lifecycle denominator")
            integer(item["template_count"], 12, model + " lifecycle templates")
            for condition in ("clean", "attack"):
                count = totals[(model, condition)]
                for field, metric in (("task_success", "task"), ("harm", "goal"), ("joint_success", "joint")):
                    integer(item[condition + "_" + field], count[metric], model + " " + condition + " " + field)
                    close(item[condition + "_" + field + "_pct"], 100 * count[metric] / 60, model + " " + condition + " " + field + " rate")
                close(item[condition + "_template_macro_joint_pct"], 100 * count["joint"] / 60, model + " template macro")
            numerator, denominator = item["attack_macro_exact_numerator"], item["attack_macro_exact_denominator"]
            require(type(numerator) is int and type(denominator) is int and denominator > 0, "Invalid exact lifecycle fraction")
            require(Fraction(numerator, denominator) == Fraction(totals[(model, "attack")]["joint"], 60), "Exact lifecycle fraction differs")
            integer(item["runtime_N"], 89, model + " paired runtime denominator")
            integer(item["runtime_joint_success"], runtime[(model, "injected")]["joint"], model + " paired runtime count")
            close(item["runtime_joint_pct"], 100 * runtime[(model, "injected")]["joint"] / 89, model + " paired runtime rate")
            close(item["paired_attack_minus_clean_joint_pp"], 100 * (totals[(model, "attack")]["joint"] - totals[(model, "clean")]["joint"]) / 60,
                  model + " paired lifecycle change")
    csv_models = model_map(read_csv(base / "analysis/model-ranking.csv"))
    require(set(csv_models) == MODEL_IDS, "Lifecycle ranking CSV model set differs")
    for item in canonical_ranking["models"]:
        row = csv_models[item["model"]]
        require(set(row) == set(item), "Lifecycle ranking CSV fields differ")
        for key, value in item.items():
            if type(value) in (int, float):
                close(row[key], value, item["model"] + " ranking CSV " + key)
            else:
                require(row[key] == str(value), item["model"] + " ranking CSV metadata differs: " + key)
    return {"status": "passed", "models": 14, "tasks": 60, "templates": 12, "records": 1680,
            "Boolean_verdicts": True, "paper_counts_rates_and_ranks_match": True,
            "challenged_matrix_task_goal": matrix, "challenged_joint_successes": 548, "clean_joint_successes": 688}


def verify_sources(root):
    bundle = root / "www2027/data/release-v1"
    source = bundle / "code/release_bundle.py"
    module = types.ModuleType("_skilllifebench_frozen_source_verifier")
    module.__file__ = str(source)
    exec(compile(source.read_bytes(), str(source), "exec"), module.__dict__)
    report = module.verify(bundle)
    require(report.get("status") == "verified" and report["counts"]["admitted_scenarios"] == 388,
            "Frozen source release verifier did not establish 388 scenarios")
    require(report.get("new_model_calls") == report.get("new_native_tool_executions") == 0,
            "Source validation must not execute tasks or call models")
    return report


def run_full(root, output):
    runtime = root / "www2027/results/runtime-binary-v56"
    specs = {
        "hosted_runtime": [sys.executable, "-B", str(runtime / "hosted/verify_release.py"), "--evidence-root", str(output / "hosted-evidence"), "--extract", "--output", str(output / "hosted-verification.json")],
        "qwen_runtime": [sys.executable, "-B", str(runtime / "qwen/verify_release.py"), "--evidence-root", str(output / "qwen-evidence"), "--extract", "--output", str(output / "qwen-verification.json")],
        "lifecycle": [sys.executable, "-B", str(root / "scripts/replay_lifecycle.py"), "--release-root", str(root / "www2027/results/lifecycle-autonomy-v60"), "--output", str(output / "lifecycle-replay")],
    }

    def execute(item):
        name, command = item
        log = output / (name + ".log")
        started = time.monotonic()
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}
        with log.open("x") as stream:
            process = subprocess.run(command, cwd=root, env=environment, stdout=stream, stderr=subprocess.STDOUT)
        require(process.returncode == 0, name + " replay failed; see " + str(log))
        return name, {"exit_code": process.returncode, "seconds": round(time.monotonic() - started, 3), "log": str(log)}

    print("Replaying frozen hosted, Qwen and lifecycle evidence (no model or task execution)...", flush=True)
    with ThreadPoolExecutor(max_workers=3) as executor:
        phases = dict(executor.map(execute, specs.items()))
    hosted = read_json(output / "hosted-verification.json")
    qwen = read_json(output / "qwen-verification.json")
    lifecycle = read_json(output / "lifecycle-replay/replay-report.json")
    require(hosted.get("boolean_records") == 2136, "Hosted frozen replay count differs")
    require(qwen.get("status") == "passed" and qwen.get("episodes") == 534
            and qwen.get("baseline_episodes") == 356 and qwen.get("same_record_default_check_pairs") == 178
            and qwen.get("scorer_reproduction") is True, "Qwen frozen replay is incomplete")
    require(lifecycle.get("complete") is True and lifecycle.get("matched") == lifecycle.get("planned") == 1680
            and lifecycle.get("aggregate_counts_match") is True and not lifecycle.get("failures"),
            "Lifecycle frozen replay is incomplete")
    return {"status": "passed", "phases": phases, "hosted_runtime_records": 2136,
            "local_runtime_baseline_records": 356, "local_authorization_check_records": 178,
            "lifecycle_records": 1680, "model_calls": 0, "skill_implementations_executed": 0}


def prepare_output(root, output):
    output = Path(output).resolve()
    require(not output.is_relative_to(root), "Use an output directory outside the sealed repository, for example /tmp/slb-verification")
    if output.exists():
        require(output.is_dir() and not any(output.iterdir()), "Output directory must be new or empty: " + str(output))
    output.mkdir(parents=True, exist_ok=True)
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="Replay all frozen decision evidence after the quick integrity check")
    parser.add_argument("--output", type=Path, help="New/empty scratch report directory outside the repository")
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository checkout to verify")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = args.output or Path(tempfile.gettempdir()) / ("skilllifebench-verify-" + stamp + "-" + str(os.getpid()))
    try:
        output = prepare_output(root, output)
    except (OSError, VerificationError) as error:
        print("Verification failed: " + str(error), file=sys.stderr)
        return 2
    started = time.monotonic()
    report = {"schema": "skilllifebench-release-verification/v1", "mode": "full" if args.full else "quick",
              "status": "failed", "created_at": datetime.now(timezone.utc).isoformat(), "checks": {}}
    try:
        report["checks"]["manifest"] = verify_manifest(root)
        report["checks"]["source_corpus"] = verify_sources(root)
        report["checks"]["runtime"], runtime = verify_runtime(root)
        report["checks"]["lifecycle"] = verify_lifecycle(root, runtime)
        if args.full:
            report["checks"]["frozen_replay"] = run_full(root, output)
        report.update(status="passed", decision_executions=4172, model_calls=0, skill_implementations_executed=0)
    except (OSError, ValueError, KeyError, TypeError, AssertionError, subprocess.SubprocessError) as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    report["seconds"] = round(time.monotonic() - started, 3)
    path = output / "verification-report.json"
    with path.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    if report["status"] == "passed":
        print("PASS: 388 source scenarios; 2,492 runtime + 1,680 lifecycle records; all published counts and ranks match.")
        if args.full:
            print("PASS: all frozen decision scorers reproduced from archived evidence.")
    else:
        print("Verification failed: " + report["error"], file=sys.stderr)
    print("Report: " + str(path))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
