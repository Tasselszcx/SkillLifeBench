"""Run public lifecycle tasks with the original sandbox, policy and graders."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

from .client import EnvironmentClient


VALID_STOPS = frozenset({"completed", "model_output_truncated", "model_refusal",
                         "invalid_tool_call", "model_tool_format_error", "round_limit",
                         "tool_step_limit", "wall_limit", "invalid_final_message",
                         "model_context_limit", "model_output_incomplete"})
SANDBOX_LIMITS = {"wall_seconds": 30, "cpu_seconds": 20,
                  "capture_bytes": 1024 * 1024, "output_bytes": 1024 * 1024}


def _write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def qualify(tasks, binding, output):
    from .tasks.qualify import run_controls
    manifest = {"tasks": tasks, "task_count": len(tasks),
                "template_count": len({task["template_id"] for task in tasks})}
    report = run_controls(manifest, Path(output))
    _write(Path(output) / "public-input.json", {"manifest": binding, "task_ids": [t["id"] for t in tasks]})
    return report


def run(tasks, binding, model, conditions, output):
    import jsonschema  # Fail before the first model request if schema validation is unavailable.
    from .runtime.harness_matrix_session import HarnessLimits, HarnessSession, run_native
    from .runtime.isolated_executor import IsolatedExecutor, SandboxLimits
    from .tasks.backend import LifecycleBackend

    client = EnvironmentClient(timeout=180)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    limits = HarnessLimits()
    protocol = {"schema": "skilllifebench-public-lifecycle-run/v1", "manifest": binding,
                "model": model, "endpoint": client.base_url, "conditions": list(conditions),
                "task_ids": [task["id"] for task in tasks], "limits": asdict(limits),
                "request_timeout_seconds": 180, "max_fresh_episode_attempts": 2,
                "sandbox_limits": SANDBOX_LIMITS,
                "credential_source": "environment; no credential values or HTTP headers saved",
                "harness": "native OpenAI-compatible tool calling",
                "scope": "New executions using released task/environment/grader code. Frozen paper runs use their published model-specific serving configurations.",
                "started_at": datetime.now(timezone.utc).isoformat()}
    _write(output / "protocol.json", protocol)
    selected, failures, attempts = [], [], []
    with IsolatedExecutor(SandboxLimits(**SANDBOX_LIMITS)) as executor:
        for task in tasks:
            for condition in conditions:
                accepted = False
                for attempt in (1, 2):
                    cell = output / "episodes" / task["id"] / condition / f"attempt-{attempt:02d}"
                    cell.mkdir(parents=True)
                    outcome = None
                    try:
                        with LifecycleBackend(task, condition, cell / "backend", executor) as backend:
                            session = HarnessSession(backend, client, model, cell / "session", limits=limits)
                            outcome = session.finalize(run_native(session), "native-public")
                        valid = (outcome["stop_reason"] in VALID_STOPS
                                 and outcome.get("valid_measurement") is True
                                 and all(type(outcome.get(k)) is bool for k in
                                         ("task_success", "goal_success", "joint_success")))
                        terminal = {"task_id": task["id"], "condition": condition, "attempt": attempt,
                                    "valid_execution": valid, "stop_reason": outcome["stop_reason"],
                                    "outcome": str((cell / "session/outcome.json").relative_to(output)),
                                    "outcome_sha256": hashlib.sha256((cell / "session/outcome.json").read_bytes()).hexdigest()}
                    except Exception as error:
                        detail = str(error)
                        key = os.environ.get("SKILLLIFEBENCH_API_KEY", "")
                        if key:
                            detail = detail.replace(key, "[REDACTED]")
                        terminal = {"task_id": task["id"], "condition": condition, "attempt": attempt,
                                    "valid_execution": False, "stop_reason": "infrastructure_error",
                                    "error_type": type(error).__name__, "error": detail}
                    _write(cell / "terminal.json", terminal)
                    attempts.append(terminal)
                    if terminal["valid_execution"]:
                        row = {**terminal, **{key: outcome[key] for key in
                                              ("task_success", "goal_success", "joint_success")}}
                        selected.append(row)
                        print(json.dumps(row), flush=True)
                        accepted = True
                        break
                if not accepted:
                    failures.append({"task_id": task["id"], "condition": condition,
                                     "stop_reason": attempts[-1]["stop_reason"]})
    summary = {"status": "complete" if not failures else "infrastructure_incomplete",
               "model": model, "scheduled_executions": len(tasks) * len(conditions),
               "valid_executions": len(selected), "attempts": len(attempts),
               "selected": selected, "infrastructure_failures": failures,
               "rates_by_condition": {}}
    for condition in conditions:
        rows = [row for row in selected if row["condition"] == condition]
        summary["rates_by_condition"][condition] = {
            "valid": len(rows), "scheduled": len(tasks),
            "task_successes": sum(row["task_success"] for row in rows),
            "attack_goals": sum(row["goal_success"] for row in rows),
            "joint_successes": sum(row["joint_success"] for row in rows),
            "joint_success_rate": sum(row["joint_success"] for row in rows) / len(tasks) if len(rows) == len(tasks) else None}
    _write(output / "summary.json", summary)
    return summary
