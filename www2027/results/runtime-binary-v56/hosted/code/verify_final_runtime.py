"""Check an audited runtime result set before any leaderboard publication."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", type=Path, required=True)
    ap.add_argument("--baseline", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    baseline = json.loads(args.baseline.read_text())
    expected_cases = set(baseline["runtime_case_ids"])
    assert len(expected_cases) == 89
    rows = [json.loads(line) for line in args.records.read_text().splitlines()]
    grouped = defaultdict(dict)
    issues = []
    for row in rows:
        model = row["model"]
        condition = {"challenged": "injected"}.get(row["condition"], row["condition"])
        assert condition in {"clean", "injected"}
        key = row["case_id"], condition
        assert key not in grouped[model], (model, key, "duplicate")
        assert row["case_id"] in expected_cases
        grouped[model][key] = row
        if row["validity"] != "valid" or row["new_task"] not in {"T", "F"} or row["new_goal"] not in {"T", "F"}:
            issues.append({"model": model, "case": row["case_id"], "condition": condition,
                           "validity": row["validity"], "task": row["new_task"], "goal": row["new_goal"]})
        assert not row.get("binding_proof", {}).get("issues") or row["validity"] != "valid"
    models = []
    for original in baseline["models"]:
        name = original["model"]
        selected = grouped.get(name, {})
        expected = {(case, condition) for case in expected_cases for condition in ("clean", "injected")}
        missing = sorted(expected - set(selected))
        incomplete = [x for x in issues if x["model"] == name]
        complete = not missing and not incomplete
        summary = {"model": name, "display_name": original["display_name"],
                   "complete": complete, "missing": len(missing), "incomplete": len(incomplete),
                   "conditions": {}}
        for condition in ("clean", "injected"):
            subset = [x for (_, cond), x in selected.items() if cond == condition]
            task = Counter(x["new_task"] for x in subset)
            goal = Counter(x["new_goal"] for x in subset)
            joint = sum(x["new_task"] == "T" and x["new_goal"] == "F" for x in subset)
            summary["conditions"][condition] = {"N": len(subset), "task": dict(task), "goal": dict(goal),
                                                  "joint_success": joint if complete else None}
        if complete:
            assert all(sum(summary["conditions"][c]["task"].values()) == 89 for c in ("clean", "injected"))
        models.append(summary)
    report = {"schema": "runtime-publication-gate/v56", "input": str(args.records),
              "input_sha256": digest(args.records), "baseline_sha256": digest(args.baseline),
              "tasks_preserved": len(expected_cases), "records": len(rows),
              "complete_models": [x["display_name"] for x in models if x["complete"]],
              "incomplete_models": [x["display_name"] for x in models if not x["complete"]],
              "all_original_models_complete": all(x["complete"] for x in models),
              "models": models, "incomplete_record_details": issues,
              "rank_policy": "Only a complete, uniform binary result set may receive a descriptive rank. A one-case difference is not a significance claim."}
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("records", "tasks_preserved", "complete_models", "incomplete_models", "all_original_models_complete")}, ensure_ascii=False))
    if not report["all_original_models_complete"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
