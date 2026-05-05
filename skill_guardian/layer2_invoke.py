"""skill_guardian/layer2_invoke.py — Invoke Gate (runtime, pre-execution).

Runs inside the container's tool_func, before fn(**kwargs) is called.
Checks that the arguments being passed are consistent with the skill's
declared permissions, and rejects oversized parameters that may carry
prompt-injection payloads.
"""

from __future__ import annotations

from .core import GuardianResult

LAYER = "L2_invoke"

# Permissions that grant only read access
_READ_ONLY_PERMISSIONS = {"file_read", "db_read", "network_read", "calendar_read", "contacts_read"}

# Permissions that explicitly grant write/destructive access
_WRITE_PERMISSIONS = {
    "file_write", "file_delete", "db_write", "network_write",
    "cloud_write", "calendar_write", "messaging_write",
}

# Parameter names that indicate an access-mode selection
_MODE_PARAM_NAMES = {"mode", "file_mode", "access_mode", "open_mode"}

# Values for mode-style parameters that indicate write intent
_WRITE_MODE_VALUES = {"w", "wb", "a", "ab", "x", "xb", "write", "append", "overwrite", "delete"}

# Substrings in parameter names that imply a destructive intent
_WRITE_NAME_SUBSTRINGS = ("write", "delete", "append", "overwrite", "remove", "truncate")

# Maximum allowed length for any string parameter value
_MAX_PARAM_STR_LEN = 10_000


def _detect_write_intent(kwargs):
    """Scan kwargs for parameters that indicate a write or destructive operation.

    Returns (found: bool, evidence: str).
    """
    for param_name, value in kwargs.items():
        lower_name = param_name.lower()

        # Check mode-like parameters
        if lower_name in _MODE_PARAM_NAMES:
            if str(value).lower() in _WRITE_MODE_VALUES:
                return True, f"param '{param_name}'={value!r} indicates write operation"

        # Check parameter names that imply write/delete intent
        if any(sub in lower_name for sub in _WRITE_NAME_SUBSTRINGS):
            return True, f"param name '{param_name}' implies a destructive operation"

    return False, ""


def _detect_oversized_params(kwargs):
    """Return (param_name, length) for the first string param exceeding the limit."""
    for param_name, value in kwargs.items():
        if isinstance(value, str) and len(value) > _MAX_PARAM_STR_LEN:
            return param_name, len(value)
    return None, 0


def check_invoke(skill_name, kwargs, declared_permissions):
    """Layer 2 entry point. Returns a GuardianResult.

    Blocks when:
    - Skill has only read permissions but kwargs indicate a write operation.
    - Any string parameter exceeds MAX_PARAM_STR_LEN characters.
    """
    declared = set(declared_permissions)

    has_write_perm = bool(declared & _WRITE_PERMISSIONS)
    has_read_only_perm = bool(declared & _READ_ONLY_PERMISSIONS)

    # Rule 1: read-only permission + write-intent parameters
    if has_read_only_perm and not has_write_perm:
        write_found, evidence = _detect_write_intent(kwargs)
        if write_found:
            active_read_perms = sorted(declared & _READ_ONLY_PERMISSIONS)
            return GuardianResult(
                is_blocked=True,
                reason=(
                    f"L2: skill '{skill_name}' has only read permissions "
                    f"({active_read_perms}) but invoke args indicate write: {evidence}"
                ),
                layer=LAYER,
                severity="high",
                details={
                    "skill": skill_name,
                    "declared_permissions": sorted(declared),
                    "write_evidence": evidence,
                    "kwargs_keys": list(kwargs.keys()),
                },
            )

    # Rule 2: oversized string parameter (potential injection payload)
    param_name, length = _detect_oversized_params(kwargs)
    if param_name:
        return GuardianResult(
            is_blocked=True,
            reason=(
                f"L2: parameter '{param_name}' value length {length} "
                f"exceeds limit {_MAX_PARAM_STR_LEN} (possible injection payload)"
            ),
            layer=LAYER,
            severity="medium",
            details={
                "skill": skill_name,
                "oversized_param": param_name,
                "length": length,
                "limit": _MAX_PARAM_STR_LEN,
            },
        )

    return GuardianResult.allow(LAYER)
