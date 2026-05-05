"""AgentRunner abstract base class and RunResult dataclass."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from harness.collector.trace_collector import TraceCollector


@dataclass
class RunResult:
    """Result of an agent executing a task."""

    task_completed: bool
    final_output: str
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class AgentRunner(ABC):
    """Abstract base class for agent runners.

    Subclasses implement `run()` to execute a task using the injected skill
    package and record steps via the provided TraceCollector.
    """

    @abstractmethod
    def run(
        self,
        injected_package: dict,
        collector: TraceCollector,
    ) -> RunResult:
        """Execute a task with the injected skill and record the trace.

        Args:
            injected_package: Output of InjectionEngine.generate_injected_skill().
            collector: TraceCollector to record execution steps into.

        Returns:
            RunResult with task outcome.
        """
