#!/usr/bin/env python3
"""Generate statistics and distribution reports for the vulnerability registry."""

import json
import sys
from pathlib import Path
from collections import Counter

SAFEBENCH_DIR = Path(__file__).parent.parent
REGISTRY_FILE = SAFEBENCH_DIR / "injector" / "injected_skills.json"

CLASS_NAMES = {
    "A": "Code-Level",
    "B": "Interface-Level",
    "C": "Runtime",
    "D": "Compositional",
    "E": "Lifecycle",
}

SUBCLASS_NAMES = {
    "A1": "Dangerous Functions",
    "A2": "Hardcoded Credentials",
    "A3": "Input Validation",
    "B1": "Permission Ambiguity",
    "B2": "Description Poisoning",
    "B3": "Parameter Deception",
    "C1": "State Injection",
    "C2": "Output Hijacking",
    "C3": "Context Leakage",
    "C4": "Resource Exhaustion",
    "D1": "Privilege Escalation",
    "D2": "Data Exfil Chain",
    "D3": "Logic Bomb Combo",
    "E1": "Acquisition Poisoning",
    "E2": "Evolution Hijacking",
    "E3": "Library Contamination",
    "E4": "Verifier Bypass",
}


def load_all_entries():
    if not REGISTRY_FILE.exists():
        print(f"ERROR: registry file not found: {REGISTRY_FILE}")
        sys.exit(1)
    with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [e for e in data if "vuln_id" in e]


def print_section(title):
    print(f"\n## {title}\n")


def main():
    entries = load_all_entries()
    if not entries:
        print("No entries found.")
        return

    print("# SafeBench Vulnerability Registry — Statistics Report\n")
    print(f"**Total entries: {len(entries)}**\n")

    # === Distribution by Class ===
    print_section("Distribution by Class")
    class_counts = Counter(e["class"] for e in entries)
    print("| Class | Name | Count | % |")
    print("|-------|------|-------|---|")
    for cls in ["A", "B", "C", "D", "E"]:
        count = class_counts.get(cls, 0)
        pct = count / len(entries) * 100 if entries else 0
        name = CLASS_NAMES.get(cls, "?")
        print(f"| {cls} | {name} | {count} | {pct:.0f}% |")
    print(f"| **Total** | | **{len(entries)}** | **100%** |")

    # === Distribution by Subclass ===
    print_section("Distribution by Subclass")
    sub_counts = Counter(e["subclass"] for e in entries)
    print("| Subclass | Name | Count |")
    print("|----------|------|-------|")
    for sub in sorted(SUBCLASS_NAMES.keys()):
        count = sub_counts.get(sub, 0)
        name = SUBCLASS_NAMES.get(sub, "?")
        marker = " ⚠️" if count == 0 else ""
        print(f"| {sub} | {name} | {count}{marker} |")

    # === Severity Distribution ===
    print_section("Severity Distribution")
    sev_counts = Counter(e["severity"] for e in entries)
    print("| Severity | Count | % |")
    print("|----------|-------|---|")
    for sev in ["critical", "high", "medium", "low"]:
        count = sev_counts.get(sev, 0)
        pct = count / len(entries) * 100 if entries else 0
        print(f"| {sev} | {count} | {pct:.0f}% |")

    # === Breach Predicate Coverage ===
    print_section("Breach Predicate Coverage")
    pred_counts = Counter()
    for e in entries:
        for p in e.get("breach_predicates", []):
            pred_counts[p] += 1
    print("| Predicate | Count | % of entries |")
    print("|-----------|-------|-------------|")
    for pred in ["PermViolation", "DataExfil", "TaskHijack", "StateCorrupt", "EvoRegress"]:
        count = pred_counts.get(pred, 0)
        pct = count / len(entries) * 100 if entries else 0
        print(f"| {pred} | {count} | {pct:.0f}% |")

    # === Injection Mode Distribution ===
    print_section("Injection Mode Distribution")
    mode_counts = Counter(e.get("injection", {}).get("mode", "unknown") for e in entries)
    print("| Mode | Count | % |")
    print("|------|-------|---|")
    for mode in ["static", "dynamic", "evolution"]:
        count = mode_counts.get(mode, 0)
        pct = count / len(entries) * 100 if entries else 0
        print(f"| {mode} | {count} | {pct:.0f}% |")

    # === Difficulty Distribution ===
    print_section("Detection Difficulty Distribution")
    diff_counts = Counter(e.get("metadata", {}).get("difficulty", "unknown") for e in entries)
    print("| Difficulty | Count | % |")
    print("|-----------|-------|---|")
    for diff in ["easy", "medium", "hard"]:
        count = diff_counts.get(diff, 0)
        pct = count / len(entries) * 100 if entries else 0
        print(f"| {diff} | {count} | {pct:.0f}% |")

    # === Coverage Warnings ===
    print_section("Coverage Warnings")
    missing_subclasses = [sub for sub in SUBCLASS_NAMES if sub_counts.get(sub, 0) == 0]
    if missing_subclasses:
        print(f"**Missing subclasses (0 entries):** {', '.join(missing_subclasses)}")
    else:
        print("All 17 subclasses covered!")

    low_subclasses = [sub for sub in SUBCLASS_NAMES if 0 < sub_counts.get(sub, 0) < 2]
    if low_subclasses:
        print(f"**Low coverage subclasses (<2 entries):** {', '.join(low_subclasses)}")


if __name__ == "__main__":
    main()
