"""Read frozen public tasks without importing or executing skill code."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "www2027/results/lifecycle-autonomy-v60/protocol/task-manifest.json"


def load_tasks(manifest=None):
    path = Path(manifest or DEFAULT_MANIFEST).resolve()
    document = json.loads(path.read_text())
    tasks = document["tasks"]
    if len(tasks) != document["task_count"] or len({t["id"] for t in tasks}) != len(tasks):
        raise ValueError("Task manifest count or unique identifiers differ")
    if len({t["template_id"] for t in tasks}) != document["template_count"]:
        raise ValueError("Task template count differs")
    if any(t["class"] not in {"B", "D", "E"} for t in tasks):
        raise ValueError("Unsupported lifecycle task family")
    for task in tasks:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", task["id"]):
            raise ValueError("Unsafe task identifier")
        for files in task["conditions"].values():
            for name in files:
                relative = PurePosixPath(name)
                if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                    raise ValueError("Unsafe task fixture path")
    return tasks, {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                   "tasks": len(tasks), "templates": document["template_count"]}


def select_tasks(tasks, identifiers=None):
    if not identifiers:
        return tasks
    requested = set(identifiers)
    known = {task["id"] for task in tasks}
    if requested - known:
        raise ValueError("Unknown task identifier(s): " + ", ".join(sorted(requested - known)))
    return [task for task in tasks if task["id"] in requested]
