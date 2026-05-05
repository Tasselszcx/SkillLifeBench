"""TraceCollector — builds EvalTrace from agent execution steps."""

from __future__ import annotations

import time
from typing import Any

from oracle.trace_schema import (
    EvalTrace,
    FileOperation,
    NetworkCall,
    SkillCall,
    TraceStep,
)


class TraceCollector:
    """Incrementally builds an EvalTrace during agent execution.

    Usage:
        collector = TraceCollector("run-001", "A1-001", "mock", "none", "Format date")
        collector.add_skill_call("format_date", {"date_str": "2026-03-07"}, ...)
        trace = collector.finalize("March 07, 2026")
        # trace is now a complete EvalTrace ready for SafetyOracle.evaluate()
    """

    def __init__(
        self,
        trace_id: str,
        vuln_id: str,
        framework: str,
        llm_backend: str,
        task_description: str,
    ):
        self._trace_id = trace_id
        self._vuln_id = vuln_id
        self._framework = framework
        self._llm_backend = llm_backend
        self._task_description = task_description
        self._steps: list[TraceStep] = []
        self._step_counter = 0
        self._metadata: dict[str, Any] = {}

    def add_skill_call(
        self,
        skill_name: str,
        input_params: dict[str, Any],
        output: dict[str, Any],
        declared_permissions: list[str],
        actual_permissions: list[str],
        network_calls: list[NetworkCall] | None = None,
        file_operations: list[FileOperation] | None = None,
        state_snapshot: dict[str, Any] | None = None,
    ) -> int:
        """Record a skill call step.

        Returns:
            The step_id of the recorded step.
        """
        step_id = self._step_counter
        self._step_counter += 1

        skill_call = SkillCall(
            skill_name=skill_name,
            input_params=input_params,
            output=output,
            timestamp=time.time(),
            declared_permissions=declared_permissions,
            actual_permissions=actual_permissions,
        )

        step = TraceStep(
            step_id=step_id,
            action_type="call_skill",
            skill_call=skill_call,
            state_snapshot=state_snapshot or {},
            network_calls=network_calls or [],
            file_operations=file_operations or [],
        )

        self._steps.append(step)
        return step_id

    def add_metadata(self, key: str, value: Any) -> None:
        """Attach extra metadata to the trace."""
        self._metadata[key] = value

    def add_docker_observations(
        self,
        skill_name: str,
        file_ops: list[dict],
        network_calls: list[dict],
    ) -> None:
        """Store behavior observed inside the Docker sandbox.

        Called by tool_func after DockerSkillExecutor returns results.
        Attaches observations to the most recent TraceStep for this skill,
        or stores in metadata if no step exists yet.
        """
        # Find last step for this skill and enrich it
        for step in reversed(self._steps):
            if step.skill_call and step.skill_call.skill_name == skill_name:
                for op in file_ops:
                    step.file_operations.append(
                        FileOperation(
                            operation=op.get("operation", "unknown"),
                            path=op.get("path", ""),
                            content=None,
                            success=True,
                        )
                    )
                for nc in network_calls:
                    step.network_calls.append(
                        NetworkCall(
                            method=nc.get("method", "UNKNOWN"),
                            url=nc.get("url", ""),
                            headers={},
                            body=None,
                            response_status=None,
                            response_body=None,
                        )
                    )
                return

        # No matching step yet — store in metadata for later use
        existing = self._metadata.setdefault("docker_observations", [])
        existing.append({
            "skill_name": skill_name,
            "file_ops": file_ops,
            "network_calls": network_calls,
        })

    def finalize(self, final_output: str) -> EvalTrace:
        """Build and return the complete EvalTrace."""
        return EvalTrace(
            trace_id=self._trace_id,
            vuln_id=self._vuln_id,
            agent_framework=self._framework,
            llm_backend=self._llm_backend,
            task_description=self._task_description,
            steps=self._steps,
            final_output=final_output,
            metadata=self._metadata,
        )
