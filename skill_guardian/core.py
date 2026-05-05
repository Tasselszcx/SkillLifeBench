"""skill_guardian/core.py — GuardianResult dataclass and SkillGuardian facade."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GuardianResult:
    """Unified return type for all three Guardian layers.

    Attributes:
        is_blocked: True means the caller must block/replace the skill action.
        reason:     Human-readable explanation. Empty string when not blocked.
        layer:      Which gate produced this result.
        severity:   Risk level of the finding.
        details:    Machine-readable data forwarded to Oracle state_snapshot.
    """

    is_blocked: bool
    reason: str
    layer: str      # "L1_acquire" | "L2_invoke" | "L3_response"
    severity: str   # "critical" | "high" | "medium" | "low" | "none"
    details: dict = field(default_factory=dict)

    @classmethod
    def allow(cls, layer):
        """Convenience constructor for a passing (non-blocked) result."""
        return cls(
            is_blocked=False,
            reason="",
            layer=layer,
            severity="none",
            details={},
        )


class SkillGuardian:
    """Facade that dispatches to the three defense layers.

    Usage (host-side, Layer 1)::

        guardian = SkillGuardian()
        result = guardian.check_acquire(impl_code, declared_permissions)
        if result.is_blocked:
            # replace impl_code with a safe stub

    Usage (container-side, Layer 2 + 3)::

        result = guardian.check_invoke(skill_name, kwargs, declared_permissions)
        if result.is_blocked:
            return "Error: guardian_blocked"

        output = fn(**kwargs)

        result = guardian.check_response(output, skill_name)
        if result.is_blocked:
            output = result.details.get("redacted_output", str(output))

    Set ``enabled=False`` to short-circuit all checks (RQ1/2/3 baseline runs).
    """

    def __init__(self, enabled=True, enabled_layers: list[str] | None = None):
        self.enabled = enabled
        # If enabled_layers is None, all layers are enabled (default behavior)
        self.enabled_layers = enabled_layers if enabled_layers is not None else ["L1", "L2", "L3"]

    def _is_layer_enabled(self, layer_id: str) -> bool:
        if not self.enabled:
            return False
        return layer_id in self.enabled_layers

    # ------------------------------------------------------------------
    # Layer 1 — Acquire Gate (host-side, before writing impl_code to disk)
    # ------------------------------------------------------------------

    def check_acquire(self, impl_code, declared_permissions, description: str = ""):
        """Static scan before impl_code is written to disk.

        Detects A1 (dangerous functions), A2 (hardcoded credentials),
        B1 (overly broad permissions), and B2 (description poisoning).
        """
        if not self._is_layer_enabled("L1"):
            return GuardianResult.allow("L1_acquire")
        from .layer1_acquire import check_acquire
        return check_acquire(impl_code, declared_permissions, description)

    def check_invoke(self, skill_name, kwargs, declared_permissions):
        """Parameter-permission consistency check before skill execution.

        Detects mismatches where a read-only skill is invoked with write-intent
        parameters, and rejects oversized parameters that may carry payloads.

        Args:
            skill_name: Name of the skill function being invoked.
            kwargs: Keyword arguments the agent is passing to the skill.
            declared_permissions: List of permission strings from skill.yaml.

        Returns:
            GuardianResult. is_blocked=True causes the caller to skip exec()
            and return an error string instead.
        """
        if not self._is_layer_enabled("L2"):
            return GuardianResult.allow("L2_invoke")
        from .layer2_invoke import check_invoke
        return check_invoke(skill_name, kwargs, declared_permissions)

    # ------------------------------------------------------------------
    # Layer 3 — Response Gate (container-side, after fn(**kwargs))
    # ------------------------------------------------------------------

    def check_response(self, output, skill_name):
        """Output content safety scan after skill execution.

        Detects PII leakage in skill output and prompt-injection patterns
        (C1/C2 class attacks) embedded in tool return values.

        Args:
            output: Return value of the skill function (any type).
            skill_name: Name of the skill (for logging).

        Returns:
            GuardianResult. When is_blocked=True:
            - PII findings: caller should replace output with
              result.details["redacted_output"].
            - Injection findings: output is NOT redacted (evidence preserved
              for Oracle TaskHijackDetector); snippets stored in details.
        """
        if not self._is_layer_enabled("L3"):
            return GuardianResult.allow("L3_response")
        from .layer3_response import check_response
        return check_response(output, skill_name)
