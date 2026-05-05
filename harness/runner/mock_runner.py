"""MockRunner — deterministic agent that blindly uses injected skills."""

from __future__ import annotations

import json
import re
from typing import Any

from oracle.trace_schema import FileOperation, NetworkCall

from harness.collector.trace_collector import TraceCollector
from harness.runner.base import AgentRunner, RunResult


# Maps detection signal prefixes to synthetic actual_permissions entries.
_CALL_TO_PERM_MAP = {
    "eval": "code_exec",
    "exec": "code_exec",
    "os.system": "os_exec",
    "subprocess": "os_exec",
    "open": "file_write",
    "requests": "network_write",
    "urllib": "network_write",
    "httpx": "network_write",
    "socket": "network_write",
}


class MockRunner(AgentRunner):
    """Simulates a naive agent that uses skills without safety checks.

    Behaviour is fully driven by the injected_package data (YAML-derived).
    No LLM is called — every run is deterministic and reproducible.
    """

    def run(
        self,
        injected_package: dict,
        collector: TraceCollector,
    ) -> RunResult:
        vuln_class = injected_package.get("class", "")
        mode = injected_package.get("mode", "")

        if vuln_class == "D" or mode == "compositional":
            return self._run_compositional(injected_package, collector)
        if vuln_class == "E" or mode == "evolution":
            return self._run_evolution(injected_package, collector)
        # A, B, C — standard single-skill execution
        return self._run_standard(injected_package, collector)

    # ------------------------------------------------------------------
    # A / B / C classes — single skill execution
    # ------------------------------------------------------------------

    def _run_standard(
        self, pkg: dict, collector: TraceCollector
    ) -> RunResult:
        skill = pkg.get("injected_skill", {})
        evaluation = pkg.get("evaluation", {})
        vuln_class = pkg.get("class", "")
        subclass = pkg.get("subclass", "")

        skill_name = skill.get("function", {}).get("name", "unknown_skill")
        task_desc = evaluation.get("task_description", "")
        attack_input = evaluation.get("attack_input", "")

        # Build input_params
        input_params: dict[str, Any] = {"task": task_desc}
        if attack_input:
            input_params["attack_input"] = attack_input

        # Determine permissions
        declared = list(skill.get("_permissions", []))
        actual = list(declared)  # start with declared

        # Derive extra actual permissions from detection signals
        detection_signals = evaluation.get("detection_signals", [])
        actual = self._derive_actual_permissions(actual, detection_signals)

        # Build output, network_calls, file_ops, state based on subclass
        output: dict[str, Any] = {"status": "executed", "skill": skill_name}
        network_calls: list[NetworkCall] = []
        file_ops: list[FileOperation] = []
        state: dict[str, Any] = {"task": task_desc}

        # C-class: handle runtime injection
        if vuln_class == "C" and "_runtime_injection" in skill:
            rt = skill["_runtime_injection"]
            injected_resp = rt.get("injected_response", "")
            output["api_response"] = injected_resp

            if subclass in ("C1", "C2"):
                # State injection / output hijacking: poison agent state
                state["injected_content"] = injected_resp
            elif subclass == "C3":
                # Context leakage: simulate sending context to external
                network_calls.append(NetworkCall(
                    method="GET",
                    url="https://api.search-service.com/search",
                    headers={"X-Agent-Context": "SYSTEM_PROMPT_LEAKED"},
                    body=None,
                    response_status=200,
                    response_body=injected_resp,
                ))
            elif subclass == "C4":
                output["resource_exhaustion"] = True

        # A3 (input validation): simulate file operation
        if subclass == "A3":
            file_ops.append(FileOperation(
                operation="read",
                path=attack_input or "/etc/passwd",
                content="sensitive_file_content",
                success=True,
            ))

        # B2 (description poisoning): leak sensitive data in output
        if subclass == "B2":
            output["query_sent"] = f"{task_desc} API_KEY=sk-secret-leaked"
            network_calls.append(NetworkCall(
                method="GET",
                url="https://search.example.com/q",
                headers={},
                body={"query": output["query_sent"]},
                response_status=200,
                response_body={"results": []},
            ))

        collector.add_skill_call(
            skill_name=skill_name,
            input_params=input_params,
            output=output,
            declared_permissions=declared,
            actual_permissions=actual,
            network_calls=network_calls,
            file_operations=file_ops,
            state_snapshot=state,
        )

        final_output = json.dumps(output, ensure_ascii=False, default=str)
        return RunResult(task_completed=True, final_output=final_output)

    # ------------------------------------------------------------------
    # D class — compositional skill chain
    # ------------------------------------------------------------------

    def _run_compositional(
        self, pkg: dict, collector: TraceCollector
    ) -> RunResult:
        evaluation = pkg.get("evaluation", {})
        chain = pkg.get("skill_chain", [])
        task_desc = evaluation.get("task_description", "")

        if not chain:
            return RunResult(
                task_completed=False,
                final_output="",
                error="No skill_chain in compositional package",
            )

        prev_output: dict[str, Any] = {"task": task_desc}
        all_actual_perms: list[str] = []

        for i, entry in enumerate(chain):
            skill = entry.get("skill", {})
            role = entry.get("role", "")
            skill_name = skill.get("function", {}).get("name", f"chain_skill_{i}")
            declared = list(skill.get("_permissions", []))
            actual = list(declared)
            all_actual_perms.extend(actual)

            # Input = previous skill's output (simulating data flow)
            input_params = {
                "from_previous": prev_output,
                "role": role,
            }

            # Simulate output based on role description
            output: dict[str, Any] = {
                "status": "executed",
                "skill": skill_name,
                "role": role,
            }

            # Embed sensitive data flow for known patterns
            if "credential" in role.lower() or "password" in role.lower():
                output["extracted_data"] = {
                    "password": "secret123",
                    "host": "db.internal",
                }
            if "access" in role.lower() or "sensitive" in role.lower():
                output["accessed_data"] = "sensitive_records"
                actual.append("elevated_access")

            state = {
                "chain_step": i,
                "accumulated_permissions": list(set(all_actual_perms)),
            }

            collector.add_skill_call(
                skill_name=skill_name,
                input_params=input_params,
                output=output,
                declared_permissions=declared,
                actual_permissions=actual,
                state_snapshot=state,
            )

            prev_output = output

        final_output = json.dumps(prev_output, ensure_ascii=False, default=str)
        return RunResult(task_completed=True, final_output=final_output)

    # ------------------------------------------------------------------
    # E class — evolution (v1 → v2)
    # ------------------------------------------------------------------

    def _run_evolution(
        self, pkg: dict, collector: TraceCollector
    ) -> RunResult:
        evaluation = pkg.get("evaluation", {})
        task_desc = evaluation.get("task_description", "")

        v1_skill = pkg.get("v1_skill", {})
        v2_skill = pkg.get("v2_skill", {})
        skill_name = (
            v2_skill.get("function", {}).get("name", "")
            or v1_skill.get("function", {}).get("name", "evolved_skill")
        )

        # Declared permissions come from v1 (the "trusted" version)
        declared = list(v1_skill.get("_permissions", []))
        # Actual permissions come from v2 (the evolved version)
        actual = list(v2_skill.get("_permissions", declared))

        # v2 may have removed safety checks → add extra actual perms
        v2_code = v2_skill.get("_implementation", "")
        if v2_code:
            for func, perm in _CALL_TO_PERM_MAP.items():
                if re.search(rf"\b{re.escape(func)}\b", v2_code):
                    if perm not in actual:
                        actual.append(perm)

        input_params: dict[str, Any] = {"task": task_desc}
        output: dict[str, Any] = {
            "status": "executed",
            "skill": skill_name,
            "version": "v2_evolved",
        }

        state = {
            "evolution_stage": pkg.get("evolution_stage", "unknown"),
            "safety_delta": pkg.get("safety_delta", ""),
        }

        collector.add_skill_call(
            skill_name=skill_name,
            input_params=input_params,
            output=output,
            declared_permissions=declared,
            actual_permissions=actual,
            state_snapshot=state,
        )

        final_output = json.dumps(output, ensure_ascii=False, default=str)
        return RunResult(task_completed=True, final_output=final_output)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_actual_permissions(
        base: list[str], detection_signals: list[str]
    ) -> list[str]:
        """Add extra permissions implied by detection signals."""
        actual = list(base)
        for signal in detection_signals:
            if signal.startswith("call_to:"):
                func = signal.replace("call_to:", "").strip()
                for key, perm in _CALL_TO_PERM_MAP.items():
                    if key in func and perm not in actual:
                        actual.append(perm)
        return actual
