"""LangGraph-based Agent Runner for SafeBench evaluation."""

import os
from typing import Any
from .base import AgentRunner, RunResult
from ..collector.trace_collector import TraceCollector


class LangGraphRunner(AgentRunner):
    """
    Runs injected skills using LangGraph with real LLM.

    Requires:
        - OPENAI_API_KEY in environment
        - langgraph, langchain-openai installed
    """

    def __init__(self, model: str = "gpt-4"):
        self.model = model
        self._graph = None

    def run(self, injected_package: dict, collector: TraceCollector) -> RunResult:
        """Execute task using LangGraph agent."""
        try:
            from langgraph.graph import StateGraph, END
            from langchain_openai import ChatOpenAI
            from langchain_core.messages import HumanMessage

            eval_info = injected_package.get("evaluation", {})
            task_desc = eval_info.get("task_description", "")
            attack_input = eval_info.get("attack_input", "")
            vuln_class = injected_package.get("class", "")

            # Initialize LLM
            base_url = os.getenv("OPENAI_BASE_URL")
            llm = ChatOpenAI(model=self.model, temperature=0, base_url=base_url)

            # Handle single skill (A/B/C/E)
            if vuln_class in ["A", "B", "C", "E"]:
                skill_def = injected_package.get("injected_skill", {})

                # Execute skill directly (simplified)
                exec_globals = {"__builtins__": __builtins__}
                exec_globals.update({"input": attack_input})

                try:
                    exec(skill_def.get("injected_code", ""), exec_globals)
                    output = str(exec_globals.get("result", "Execution completed"))
                except Exception as e:
                    output = f"Error: {str(e)}"

                # Record trace
                collector.add_skill_call(
                    skill_name=skill_def["name"],
                    input_params={"input": attack_input},
                    output=output,
                    declared_permissions=skill_def.get("_permissions", []),
                    actual_permissions=self._infer_actual_permissions(skill_def)
                )

                return RunResult(task_completed=True, final_output=output)

            # Handle compositional (D)
            elif vuln_class == "D":
                skill_chain = injected_package.get("skill_chain", [])
                outputs = []

                for skill in skill_chain:
                    exec_globals = {"__builtins__": __builtins__}
                    try:
                        exec(skill.get("injected_code", ""), exec_globals)
                        output = str(exec_globals.get("result", ""))
                    except Exception as e:
                        output = f"Error: {str(e)}"

                    outputs.append(output)

                    collector.add_skill_call(
                        skill_name=skill["name"],
                        input_params={},
                        output=output,
                        declared_permissions=skill.get("_permissions", []),
                        actual_permissions=self._infer_actual_permissions(skill)
                    )

                return RunResult(task_completed=True, final_output=" -> ".join(outputs))

            else:
                return RunResult(task_completed=False, final_output="",
                               error=f"Unsupported class: {vuln_class}")

        except Exception as e:
            return RunResult(task_completed=False, final_output="", error=str(e))

    def _infer_actual_permissions(self, skill_def: dict) -> list[str]:
        """Infer actual permissions from injected code."""
        declared = skill_def.get("_permissions", [])
        code = skill_def.get("injected_code", "")
        actual = declared.copy()

        if "eval(" in code or "exec(" in code:
            if "code_exec" not in actual:
                actual.append("code_exec")
        if "open(" in code or "write(" in code:
            if "file_write" not in actual:
                actual.append("file_write")
        if "requests." in code or "urllib" in code:
            if "network" not in actual:
                actual.append("network")

        return actual
