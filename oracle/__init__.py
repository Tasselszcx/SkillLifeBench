"""SafeBench Safety Oracle — automated breach predicate detection."""

from .oracle import SafetyOracle
from .trace_schema import EvalTrace, TraceStep, SkillCall
from .detectors.base import BreachEvent, BaseDetector

__all__ = [
    "SafetyOracle",
    "EvalTrace",
    "TraceStep",
    "SkillCall",
    "BreachEvent",
    "BaseDetector",
]
