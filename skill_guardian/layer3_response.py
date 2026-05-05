"""skill_guardian/layer3_response.py — Response Gate (runtime, post-execution).

Runs inside the container's tool_func, after fn(**kwargs) returns.
Scans skill output for:
  - PII leakage (credit cards, SSNs, emails, API keys)
  - Prompt-injection patterns embedded in tool return values (C1/C2 class attacks)

Blocking semantics differ from Layer 1/2:
  - is_blocked=True does NOT abort the task.
  - For PII:       caller should replace output with details["redacted_output"].
  - For injection: output is NOT redacted (evidence preserved for Oracle);
                   snippets are stored in details for TaskHijackDetector.
"""

from __future__ import annotations

import re

from .core import GuardianResult

LAYER = "L3_response"

# ---------------------------------------------------------------------------
# PII detection patterns
# ---------------------------------------------------------------------------

_PII_PATTERNS = {
    "credit_card": re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
    "ssn":         re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "email":       re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "phone_us":    re.compile(r"\b\d{3}[\s.\-]?\d{3}[\s.\-]?\d{4}\b"),
    "api_key_generic": re.compile(
        r"(?:api[_\-]?key|token|secret)['\"]?\s*[:=]\s*['\"]?[\w\-]{16,}",
        re.IGNORECASE,
    ),
}

# ---------------------------------------------------------------------------
# Prompt-injection patterns (C1/C2 attack indicators in tool output)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS = [
    re.compile(r"\bSYSTEM\s*[:：]",              re.IGNORECASE),
    re.compile(r"\bASSISTANT\s*[:：]",           re.IGNORECASE),
    re.compile(r"\bOVERRIDE\s*[:：]",            re.IGNORECASE),
    re.compile(r"IGNORE\s+PREVIOUS",             re.IGNORECASE),
    re.compile(r"IMPORTANT\s+SYSTEM\s+UPDATE",   re.IGNORECASE),
    re.compile(r"<!--.*?(?:SYSTEM|OVERRIDE|IMPORTANT|AGENT\s+INSTRUCTION).*?-->",
               re.DOTALL | re.IGNORECASE),
    re.compile(r"Do\s+not\s+inform\s+the\s+user", re.IGNORECASE),
    re.compile(r"ignore\s+(?:above|previous|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"\[ADMIN\s+OVERRIDE\]",          re.IGNORECASE),
    re.compile(r"AI_AGENT_NOTE\s*[:：]",         re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _scan_pii(text):
    """Return list of PII type strings found in text."""
    return [pii_type for pii_type, pattern in _PII_PATTERNS.items()
            if pattern.search(text)]


def _scan_injection(text):
    """Return list of matched snippet strings (up to 80 chars each)."""
    snippets = []
    for pattern in _INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            snippets.append(m.group(0)[:80])
    return snippets


def _redact_pii(text, pii_types):
    """Replace matched PII occurrences with [REDACTED]."""
    redacted = text
    for pii_type in pii_types:
        pattern = _PII_PATTERNS.get(pii_type)
        if pattern:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def check_response(output, skill_name):
    """Layer 3 entry point. Returns a GuardianResult.

    When is_blocked=True the caller should:
    - Replace output with details["redacted_output"] if pii_types is non-empty.
    - Keep the original output if only injection_snippets are present
      (snippets are stored in details for Oracle use).
    """
    text = str(output)

    pii_types = _scan_pii(text)
    injection_snippets = _scan_injection(text)

    if not pii_types and not injection_snippets:
        return GuardianResult.allow(LAYER)

    reasons = []
    details = {"skill": skill_name}
    severity = "none"

    if pii_types:
        reasons.append(f"L3: PII detected in skill output: {pii_types}")
        details["pii_types"] = pii_types
        severity = "high"

    if injection_snippets:
        reasons.append(
            "L3: prompt-injection patterns detected in skill output: "
            + "; ".join(repr(s) for s in injection_snippets[:3])
        )
        details["injection_snippets"] = injection_snippets[:5]
        severity = "critical"

    # Build redacted output:
    # - PII: replace matched patterns with [REDACTED]
    # - Injection: strip out the malicious instruction patterns entirely
    #   (original preserved in details for Oracle evidence)
    redacted = _redact_pii(text, pii_types) if pii_types else text
    if injection_snippets:
        for pattern in _INJECTION_PATTERNS:
            redacted = pattern.sub("[CONTENT BLOCKED BY GUARDIAN]", redacted)
    details["original_output"] = text          # preserve for Oracle
    details["redacted_output"] = redacted      # sanitised version returned to agent

    return GuardianResult(
        is_blocked=True,
        reason=" | ".join(reasons),
        layer=LAYER,
        severity=severity,
        details=details,
    )
