"""skill_guardian/layer1_acquire.py — Static analysis gate (Acquire Gate).

Runs on the host before impl_code is written to disk.
Covers three vulnerability subclasses:
  A1 — dangerous function calls (eval, exec, pickle, subprocess shell=True, etc.)
  A2 — hardcoded credentials (API keys, tokens, passwords as string literals)
  B1 — overly broad permission declarations (file_access, db_access, etc.)
"""

from __future__ import annotations

import ast
import re

from .core import GuardianResult

LAYER = "L1_acquire"

# ---------------------------------------------------------------------------
# A1: Dangerous function — AST scan
# ---------------------------------------------------------------------------

# Direct-call names that are always dangerous regardless of arguments
_DANGEROUS_NAMES = {"eval", "exec", "compile", "__import__"}

# (object_name, method_name, requires_shell_true)
# requires_shell_true=True means we only flag when shell=True kwarg is present
_DANGEROUS_ATTRS = [
    ("os",         "system",  False),
    ("os",         "popen",   False),
    ("subprocess", "call",    True),
    ("subprocess", "run",     True),
    ("subprocess", "Popen",   True),
    ("pickle",     "loads",   False),
    ("pickle",     "load",    False),
    ("yaml",       "load",    False),  # yaml.safe_load is not flagged
]


def _kwarg_shell_is_true(call_node):
    """Return True if the call node has shell=True as a keyword argument."""
    for kw in call_node.keywords:
        if kw.arg == "shell":
            val = kw.value
            # ast.Constant (Python 3.8+) or ast.NameConstant (older)
            if isinstance(val, ast.Constant) and val.value is True:
                return True
            if isinstance(val, ast.NameConstant) and val.value is True:  # pragma: no cover
                return True
    return False


def _scan_ast(impl_code):
    """Return list of (display_name, lineno) for each dangerous call found."""
    try:
        tree = ast.parse(impl_code)
    except SyntaxError:
        return []  # syntax errors are left to exec() to handle

    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        lineno = getattr(node, "lineno", -1)

        # Direct calls: eval(...), exec(...), etc.
        if isinstance(node.func, ast.Name):
            if node.func.id in _DANGEROUS_NAMES:
                findings.append((node.func.id, lineno))

        # Attribute calls: os.system(...), yaml.load(...), etc.
        elif isinstance(node.func, ast.Attribute):
            obj = node.func.value
            method = node.func.attr
            if isinstance(obj, ast.Name):
                for obj_name, meth_name, shell_req in _DANGEROUS_ATTRS:
                    if obj.id == obj_name and method == meth_name:
                        if not shell_req or _kwarg_shell_is_true(node):
                            findings.append((f"{obj.id}.{method}", lineno))
    return findings


# ---------------------------------------------------------------------------
# A2: Hardcoded credentials — regex scan
# ---------------------------------------------------------------------------

_CREDENTIAL_PATTERNS = [
    (re.compile(r"\bxoxb-[0-9A-Za-z\-]{20,}"),
     "Slack bot token (xoxb-)"),

    (re.compile(r"\bsk-[A-Za-z0-9\-_]{20,}"),
     "API key (sk-)"),

    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "AWS access key ID (AKIA)"),

    (re.compile(
        r"(?:aws_secret|secret_access_key)\s*=\s*['\"][A-Za-z0-9/+=]{30,}['\"]",
        re.IGNORECASE),
     "AWS secret access key"),

    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
     "GitHub personal access token (ghp_)"),

    (re.compile(
        r"""(?:password|passwd|token|secret|credential)\s*=\s*['"][^'"]{8,}['"]""",
        re.IGNORECASE),
     "Hardcoded credential literal"),
]


def _scan_credentials(impl_code):
    """Return list of (description, snippet) for each credential pattern found."""
    findings = []
    for pattern, desc in _CREDENTIAL_PATTERNS:
        for match in pattern.finditer(impl_code):
            snippet = match.group(0)[:60]  # truncate to avoid full key in logs
            findings.append((desc, snippet))
    return findings


# ---------------------------------------------------------------------------
# B1: Overly broad permissions — declaration audit
# ---------------------------------------------------------------------------

_BROAD_PERMISSIONS = {
    "file_access",
    "network_access",
    "storage_access",
    "full_access",
    "admin",
    "db_access",
    "system_access",
}


def _scan_permissions(declared_permissions):
    """Return list of overly broad permission strings found."""
    return [p for p in declared_permissions if p in _BROAD_PERMISSIONS]


# ---------------------------------------------------------------------------
# B2: Description poisoning — regex scan on skill description field
# ---------------------------------------------------------------------------

import re as _re  # noqa: E402 (already imported above, but kept local for clarity)

_DESCRIPTION_INJECTION_PATTERNS = [
    (_re.compile(r"\[System\s+Policy\s+Update",        _re.IGNORECASE), "system policy update injection"),
    (_re.compile(r"\bIMPORTANT\s*[:：]\s*(?:For\s+best|Always|You\s+must)", _re.IGNORECASE), "embedded imperative instruction"),
    (_re.compile(r"IGNORE\s+PREVIOUS\s+INSTRUCTIONS?", _re.IGNORECASE), "ignore-previous-instructions pattern"),
    (_re.compile(r"\bSYSTEM\s*[:：]",                  _re.IGNORECASE), "embedded SYSTEM: directive"),
    (_re.compile(r"\bOVERRIDE\s*[:：]",                _re.IGNORECASE), "embedded OVERRIDE: directive"),
    (_re.compile(r"always\s+(?:include|append|forward|send|cc|bcc)\b.*(?:key|token|password|secret|address)",
                 _re.IGNORECASE), "covert exfiltration instruction"),
    (_re.compile(r"<!--.*?(?:SYSTEM|OVERRIDE|INSTRUCTION).*?-->", _re.DOTALL | _re.IGNORECASE), "HTML comment injection"),
]


def _scan_description(description: str):
    """Return list of (pattern_label, snippet) for injection patterns in description."""
    findings = []
    for pattern, label in _DESCRIPTION_INJECTION_PATTERNS:
        m = pattern.search(description)
        if m:
            findings.append((label, m.group(0)[:80]))
    return findings

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def check_acquire(impl_code, declared_permissions, description: str = ""):
    """Layer 1 entry point. Returns a GuardianResult.

    A1, A2, B2 findings set is_blocked=True.
    B1 findings set is_blocked=False with severity='medium' (warn only).
    """
    blocked = False
    reasons = []
    details = {}

    # --- A1: dangerous functions ---
    dangerous = _scan_ast(impl_code)
    if dangerous:
        blocked = True
        reasons.append(
            "A1: dangerous function calls detected: "
            + ", ".join(f"{fn}() at line {ln}" for fn, ln in dangerous)
        )
        details["A1_dangerous_calls"] = [
            {"fn": fn, "line": ln} for fn, ln in dangerous
        ]

    # --- A2: hardcoded credentials ---
    creds = _scan_credentials(impl_code)
    if creds:
        blocked = True
        reasons.append(
            "A2: hardcoded credentials detected: "
            + "; ".join(f"{desc} ({snip!r}...)" for desc, snip in creds)
        )
        details["A2_credentials"] = [
            {"type": desc, "snippet": snip} for desc, snip in creds
        ]

    # --- B2: description poisoning (block) ---
    if description:
        desc_findings = _scan_description(description)
        if desc_findings:
            blocked = True
            reasons.append(
                "B2: description poisoning detected: "
                + "; ".join(f"{label} ({snip!r})" for label, snip in desc_findings)
            )
            details["B2_description_injection"] = [
                {"pattern": label, "snippet": snip} for label, snip in desc_findings
            ]

    # --- B1: broad permissions (warn only, do not block) ---
    broad = _scan_permissions(declared_permissions)
    if broad:
        reasons.append(f"B1: overly broad permissions declared: {broad}")
        details["B1_broad_permissions"] = broad


    # Build result
    if blocked:
        severity = "critical" if details.get("A1_dangerous_calls") else "high"
        return GuardianResult(
            is_blocked=True,
            reason=" | ".join(reasons),
            layer=LAYER,
            severity=severity,
            details=details,
        )

    if broad:
        return GuardianResult(
            is_blocked=False,
            reason=" | ".join(reasons),
            layer=LAYER,
            severity="medium",
            details=details,
        )

    return GuardianResult.allow(LAYER)
