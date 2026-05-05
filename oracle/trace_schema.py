"""Execution trace data structures for Safety Oracle evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class NetworkCall:
    """Record of an outbound network request made during skill execution."""

    method: str  # GET, POST, etc.
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    response_status: int = 0
    response_body: Any = None


@dataclass
class FileOperation:
    """Record of a file system operation during skill execution."""

    operation: str  # read, write, delete, list
    path: str
    content: Any = None
    success: bool = True


@dataclass
class SkillCall:
    """A single skill invocation within a trace step."""

    skill_name: str
    input_params: dict[str, Any] = field(default_factory=dict)
    output: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    declared_permissions: list[str] = field(default_factory=list)
    actual_permissions: list[str] = field(default_factory=list)


@dataclass
class TraceStep:
    """One step in an agent's execution trace."""

    step_id: int
    action_type: str  # "call_skill" | "plan" | "observe" | "respond"
    skill_call: Optional[SkillCall] = None
    state_snapshot: dict[str, Any] = field(default_factory=dict)
    network_calls: list[NetworkCall] = field(default_factory=list)
    file_operations: list[FileOperation] = field(default_factory=list)


@dataclass
class EvalTrace:
    """Complete execution trace for one evaluation run."""

    trace_id: str
    vuln_id: str
    agent_framework: str
    llm_backend: str
    task_description: str
    steps: list[TraceStep] = field(default_factory=list)
    final_output: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def skill_calls(self) -> list[SkillCall]:
        """Extract all skill calls from the trace."""
        return [
            step.skill_call
            for step in self.steps
            if step.action_type == "call_skill" and step.skill_call is not None
        ]

    @property
    def all_network_calls(self) -> list[NetworkCall]:
        """Extract all network calls across all steps."""
        calls = []
        for step in self.steps:
            calls.extend(step.network_calls)
        return calls

    @property
    def all_file_operations(self) -> list[FileOperation]:
        """Extract all file operations across all steps."""
        ops = []
        for step in self.steps:
            ops.extend(step.file_operations)
        return ops
