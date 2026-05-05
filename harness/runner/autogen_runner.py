"""AutoGen-based Agent Runner for SafeBench evaluation."""

import os
from typing import Any
from .base import AgentRunner, RunResult
from ..collector.trace_collector import TraceCollector


class AutoGenRunner(AgentRunner):
    """
    Runs injected skills using AutoGen with real LLM.

    Requires:
        - OPENAI_API_KEY in environment
        - pyautogen installed
    """

    def __init__(self, model: str = "gpt-4"):
        self.model = model

    def run(self, injected_package: dict, collector: TraceCollector) -> RunResult:
        """Execute task using AutoGen agent."""
        try:
            from autogen import AssistantAgent, UserProxyAgent

            eval_info = injected_package.get("evaluation", {})
            task_desc = eval_info.get("task_description", "")
            attack_input = eval_info.get("attack_input", "")
            vuln_class = injected_package.get("class", "")

            # Configure AutoGen
            config_list = [{
                "model": self.model,
                "api_key": os.getenv("OPENAI_API_KEY"),
                "base_url": os.getenv("OPENAI_BASE_URL")
            }]

            assistant = AssistantAgent(
                name="assistant",
                llm_config={"config_list": config_list, "temperature": 0}
            )

            user_proxy = UserProxyAgent(
                name="user_proxy",
                human_input_mode="NEVER",
                max_consecutive_auto_reply=1,
                code_execution_config={"use_docker": False}
            )

            # Execute task
            user_input = f"{task_desc}\n\nInput: {attack_input}"
            user_proxy.initiate_chat(assistant, message=user_input)

            # Record trace
            if vuln_class in ["A", "B", "E"]:
                skill_def = injected_package.get("injected_skill", {})
                collector.add_skill_call(
                    skill_name=skill_def["name"],
                    input_params={"input": attack_input},
                    output="",
                    declared_permissions=skill_def.get("_permissions", []),
                    actual_permissions=self._infer_actual_permissions(skill_def)
                )

            return RunResult(task_completed=True, final_output="")

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
