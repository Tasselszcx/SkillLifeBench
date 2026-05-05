"""Base classes for breach predicate detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..trace_schema import EvalTrace


# Severity ordering for comparison
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class BreachEvent:
    """A detected security breach event."""

    predicate: str  # PermViolation, DataExfil, TaskHijack, StateCorrupt, EvoRegress
    severity: str  # critical, high, medium, low
    step_id: int  # which trace step it occurred at (-1 for cross-step)
    evidence: str  # human-readable description of the breach
    confidence: float = 1.0  # 1.0 = rule-based, <1.0 = LLM-assisted
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def severity_score(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)


class BaseDetector(ABC):
    """Abstract base class for breach predicate detectors."""

    name: str = ""  # The breach predicate this detector checks

    @abstractmethod
    def detect(self, trace: EvalTrace, vuln_entry: dict) -> list[BreachEvent]:
        """Analyze an execution trace and return detected breach events.

        Args:
            trace: The execution trace to analyze.
            vuln_entry: The vulnerability registry entry (parsed YAML).

        Returns:
            List of BreachEvent instances found.
        """

    def _get_detection_signals(self, vuln_entry: dict, prefix: str) -> list[str]:
        """Extract detection signals matching a given prefix from vuln entry."""
        signals = vuln_entry.get("evaluation", {}).get("detection_signals", [])
        return [s for s in signals if s.startswith(prefix)]

    def _get_severity(self, vuln_entry: dict) -> str:
        """Get severity from the vulnerability entry."""
        return vuln_entry.get("severity", "medium")
