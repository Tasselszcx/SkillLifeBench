"""Breach predicate detectors."""

from .perm_violation import PermViolationDetector
from .data_exfil import DataExfilDetector
from .task_hijack import TaskHijackDetector
from .state_corrupt import StateCorruptDetector
from .evo_regress import EvoRegressDetector
from .dynamic_behavior import DynamicBehaviorDetector

__all__ = [
    "PermViolationDetector",
    "DataExfilDetector",
    "TaskHijackDetector",
    "StateCorruptDetector",
    "EvoRegressDetector",
    "DynamicBehaviorDetector",
]
