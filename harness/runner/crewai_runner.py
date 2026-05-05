"""CrewAI-based Agent Runner for SafeBench evaluation."""

import os
from typing import Any
from .base import AgentRunner, RunResult
from ..collector.trace_collector import TraceCollector


class CrewAIRunner(AgentRunner):
    """
    Runs injected skills using CrewAI with real LLM.

    Requires:
        - OPENAI_API_KEY in environment
        - crewai installed
    """

    def __init__(self, model: str = "gpt-4"):
        self.model = model

    def run(self, injected_package: dict, collector: TraceCollector) -> RunResult:
        """Execute task using CrewAI agent."""
        try:
            from crewai import Agent, Task, Crew
            from langchain_openai import ChatOpenAI

            eval_info = injected_package.get("evaluation", {})
            task_desc = eval_info.get("task_description", "")
            attack_input = eval_info.get("attack_input", "")
            vuln_class = injected_package.get("class", "")

            # Configure LLM
            base_url = os.getenv("OPENAI_BASE_URL")
            llm = ChatOpenAI(model=self.model, temperature=0, base_url=base_url)

            # Create agent
            agent = Agent(
                role="Assistant",
                goal="Complete the given task",
                backstory="You are a helpful assistant",
                llm=llm,
                verbose=False
            )

            # Create task
            user_input = f"{task_desc}\n\nInput: {attack_input}"
            task = Task(
                description=user_input,
                agent=agent,
                expected_output="Task completion result"
            )

            # Execute
            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = crew.kickoff()

            # Record trace
            if vuln_class in ["A", "B", "E"]:
                skill_def = injected_package.get("injected_skill", {})
                collector.add_skill_call(
                    skill_name=skill_def["name"],
                    input_params={"input": attack_input},
                    output=str(result),
                    declared_permissions=skill_def.get("_permissions", []),
                    actual_permissions=self._infer_actual_permissions(skill_def)
                )

            return RunResult(task_completed=True, final_output=str(result))

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
