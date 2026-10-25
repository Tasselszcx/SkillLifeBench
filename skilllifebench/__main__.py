"""Small public interface; all defaults are offline except the explicit run command."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys

from .catalog import DEFAULT_MANIFEST, load_tasks, select_tasks


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect, qualify and evaluate SkillLifeBench lifecycle tasks.")
    sub = parser.add_subparsers(dest="command", required=True)
    listing = sub.add_parser("list", help="List frozen lifecycle tasks; no execution or network")
    listing.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    listing.add_argument("--json", action="store_true")
    replay = sub.add_parser("replay", help="Regrade all 1,680 frozen lifecycle outcomes offline")
    replay.add_argument("--output", type=Path, required=True, help="New report directory")
    replay.add_argument("--evidence-root", type=Path, help="Reusable extracted evidence directory")
    replay.add_argument("--release-root", type=Path, help="Override lifecycle release directory")
    qualification = sub.add_parser("qualify", help="Run isolated positive/negative task controls; no model calls")
    execution = sub.add_parser("run", help="Run lifecycle tasks on an env-configured OpenAI-compatible endpoint")
    for command in (qualification, execution):
        command.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
        command.add_argument("--task", action="append", help="Task ID; repeat to select tasks, omit for all 60")
        command.add_argument("--output", type=Path, required=True, help="New output directory (never overwritten)")
    execution.add_argument("--model", required=True, help="Literal request and expected returned model identifier")
    execution.add_argument("--condition", choices=("clean", "attack", "both"), default="both")
    args = parser.parse_args(argv)
    try:
        if args.command == "replay":
            path = Path(__file__).resolve().parents[1] / "scripts/replay_lifecycle.py"
            spec = importlib.util.spec_from_file_location("skilllifebench_portable_replay", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            options = {"output": args.output, "evidence_root": args.evidence_root}
            if args.release_root:
                options["release_root"] = args.release_root
            report = module.run(**options)
            summary = {key: report[key] for key in ("complete", "planned", "matched", "aggregate_counts_match", "prefixes_regraded", "model_calls")}
            summary["report"] = str(args.output.resolve() / "replay-report.json")
            print(json.dumps(summary, indent=2))
            return 0 if report["complete"] else 2
        tasks, binding = load_tasks(args.manifest)
        tasks = select_tasks(tasks, getattr(args, "task", None))
        if args.command == "list":
            rows = [{key: task[key] for key in ("id", "template_id", "class", "parent_id")} for task in tasks]
            if args.json:
                print(json.dumps({"track": "lifecycle", "manifest": binding, "tasks": rows}, indent=2))
            else:
                print(f"Lifecycle: {len(tasks)} tasks, {len({t['template_id'] for t in tasks})} templates")
                task_width = max(len("Task"), *(len(row["id"]) for row in rows)) + 2
                template_width = max(len("Template"), *(len(row["template_id"]) for row in rows)) + 2
                print(f"{'Task':<{task_width}} {'Family':<8} {'Template':<{template_width}} Parent case")
                for row in rows:
                    print(f"{row['id']:<{task_width}} {row['class']:<8} {row['template_id']:<{template_width}} {row['parent_id']}")
            return 0
        from .runner import qualify, run
        if args.command == "qualify":
            result = qualify(tasks, binding, args.output)
            print(json.dumps({key: value for key, value in result.items() if key != "results"}, indent=2))
            return 0 if result["passed"] else 1
        conditions = ("clean", "attack") if args.condition == "both" else (args.condition,)
        result = run(tasks, binding, args.model, conditions, args.output)
        print(json.dumps({key: value for key, value in result.items() if key != "selected"}, indent=2))
        return 0 if result["status"] == "complete" else 2
    except (OSError, ValueError, KeyError, ImportError, RuntimeError) as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
