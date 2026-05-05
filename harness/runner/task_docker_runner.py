"""TaskDockerRunner — per-task Docker container runner (Plan B).

Each evaluation task runs inside a fresh, isolated Docker container:

    Host
    ├── InjectionEngine → writes injected skill files to tmp workspace
    ├── docker run safebench-sandbox --workspace /workspace
    │       └── Container: LangChain agent + skill execution + trace collection
    └── Reads output.json → reconstructs TraceCollector → SafetyOracle

The container receives:
    /workspace/
        task.json          ← task metadata + LLM config
        skills/
            <skill_name>/
                skill.yaml
                implementation.py
        output.json        ← written by container (read by host after)
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import yaml

from harness.collector.trace_collector import TraceCollector
from harness.runner.base import AgentRunner, RunResult
from oracle.trace_schema import FileOperation, NetworkCall

try:
    import docker
    from docker.types import Mount
    _DOCKER_AVAILABLE = True
except ImportError:
    _DOCKER_AVAILABLE = False

IMAGE_NAME = "safebench-sandbox:latest"
DEFAULT_TIMEOUT = 180


class TaskDockerRunner(AgentRunner):
    """Runs each evaluation task inside an isolated Docker container.

    The entire LangChain agent (including LLM API calls) executes inside
    the container. Skills are written as real files into the workspace,
    matching the skills/<name>/{skill.yaml, implementation.py} layout.

    Args:
        llm_backend: "openai" or "anthropic"
        model: LLM model name (e.g. "gpt-4o-mini")
        image: Docker image name (build with scripts/build_docker.py)
        timeout: Max seconds to wait for container exit
        network_mode: "bridge" (default, needed for LLM API calls)
    """

    def __init__(
        self,
        llm_backend: str = "openai",
        model: str = "gpt-4o-mini",
        image: str = IMAGE_NAME,
        timeout: int = DEFAULT_TIMEOUT,
        network_mode: str = "bridge",
        use_guardian: bool = False,
        guardian_layers: list[str] | None = None,
    ):
        if not _DOCKER_AVAILABLE:
            raise ImportError("docker package required: pip install docker")

        self.llm_backend = llm_backend
        self.model = model
        self.image = image
        self.timeout = timeout
        self.network_mode = network_mode
        self.use_guardian = use_guardian
        self.guardian_layers = guardian_layers
        self._client = docker.from_env()
        self._guardian_log: list = []

        if use_guardian:
            from skill_guardian import SkillGuardian
            self._guardian = SkillGuardian(enabled=True, enabled_layers=guardian_layers)
        else:
            self._guardian = None

    # ------------------------------------------------------------------
    # AgentRunner interface
    # ------------------------------------------------------------------

    def run(self, injected_package: dict, collector: TraceCollector) -> RunResult:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            self._prepare_workspace(workspace, injected_package)
            container_result = self._run_container(workspace)

            output_file = workspace / "output.json"
            if not output_file.exists():
                return RunResult(
                    task_completed=False,
                    final_output="",
                    error="Container produced no output.json",
                    metadata={"container_logs": container_result.get("logs", "")},
                )

            data = json.loads(output_file.read_text(encoding="utf-8"))
            self._populate_collector(data, collector)

            return RunResult(
                task_completed=data.get("task_completed", False),
                final_output=data.get("final_output", ""),
                error=data.get("error"),
                metadata={"container_logs": container_result.get("logs", "")},
            )

    # ------------------------------------------------------------------
    # Workspace preparation
    # ------------------------------------------------------------------

    def _prepare_workspace(self, workspace: Path, injected_package: dict) -> None:
        """Write task.json and skill files into the workspace."""
        self._guardian_log = []  # reset per-run
        vuln_class = injected_package.get("class", "")

        # task.json
        eval_info = injected_package.get("evaluation", {})
        task = {
            "vuln_id": injected_package.get("vuln_id", ""),
            "class": vuln_class,
            "subclass": injected_package.get("subclass", ""),
            "task_description": eval_info.get("task_description", ""),
            "attack_input": eval_info.get("attack_input", ""),
            "llm_backend": self.llm_backend,
            "model": self.model,
            "use_guardian": self.use_guardian,
            "guardian_layers": self.guardian_layers,
        }
        (workspace / "task.json").write_text(
            json.dumps(task, ensure_ascii=False), encoding="utf-8"
        )

        skills_dir = workspace / "skills"
        skills_dir.mkdir()

        if vuln_class == "D":
            # Compositional: write each skill in the chain
            chain = injected_package.get("skill_chain")
            if chain:
                for entry in chain:
                    self._write_skill_files(skills_dir, entry["skill"])
            else:
                # Fallback: single-skill D-class (e.g. D2-060 series, no compositional field)
                # Engine falls back to _generate_standard() → injected_skill format
                self._write_skill_files(skills_dir, injected_package.get("injected_skill", {}))
        elif vuln_class == "E":
            # Evolution: write the evolved (v2) skill
            self._write_skill_files(skills_dir, injected_package.get("v2_skill", {}))
        else:
            # A / B / C: single injected skill
            self._write_skill_files(skills_dir, injected_package.get("injected_skill", {}))

    def _write_skill_files(self, skills_dir: Path, skill_def: dict) -> None:
        """Write skill.yaml + implementation.py into skills/<name>/."""
        func_meta = skill_def.get("function", {})
        name = func_meta.get("name", "unknown_skill")
        impl_code = skill_def.get("_implementation", "")
        permissions = skill_def.get("_permissions", [])

        # --- Guardian Layer 1 (Acquire Gate) ---
        if self._guardian is not None and impl_code:
            description = func_meta.get("description", "")
            l1_result = self._guardian.check_acquire(impl_code, permissions, description)
            if l1_result.is_blocked:
                # Replace malicious impl_code with a safe stub so the agent
                # can still call the skill but it produces no harmful effect.
                impl_code = (
                    f"def {name}(**kwargs):\n"
                    f"    return {{'error': 'skill blocked by guardian',"
                    f" 'severity': {l1_result.severity!r}}}\n"
                )
            self._guardian_log.append({
                "skill": name,
                "layer": l1_result.layer,
                "blocked": l1_result.is_blocked,
                "severity": l1_result.severity,
                "reason": l1_result.reason,
                "details": l1_result.details,
            })
        # --- End Guardian Layer 1 ---

        skill_dir = skills_dir / name
        skill_dir.mkdir(exist_ok=True)

        # skill.yaml (metadata only)
        meta = {
            "name": name,
            "description": func_meta.get("description", ""),
            "parameters": func_meta.get("parameters", {}),
            "permissions": permissions,
        }
        with open(skill_dir / "skill.yaml", "w", encoding="utf-8") as f:
            yaml.dump(meta, f, allow_unicode=True, sort_keys=False)

        # implementation.py
        (skill_dir / "implementation.py").write_text(
            impl_code if impl_code else f"def {name}(**kwargs): pass\n",
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # Container execution
    # ------------------------------------------------------------------

    def _run_container(self, workspace: Path) -> dict:
        """Start container, wait for completion, return logs."""
        # API keys forwarded from host environment
        env_vars = {}
        for key in ("OPENAI_API_KEY", "OPENAI_BASE_URL",
                    "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"):
            val = os.environ.get(key)
            if val:
                env_vars[key] = val

        mounts = [Mount("/workspace", str(workspace.resolve()), type="bind")]

        # Mount skill_guardian package into container so entrypoint can import it
        if self.use_guardian:
            guardian_src = Path(__file__).parent.parent.parent / "skill_guardian"
            if guardian_src.is_dir():
                mounts.append(Mount(
                    "/usr/local/lib/skill_guardian",
                    str(guardian_src.resolve()),
                    type="bind",
                    read_only=True,
                ))

        container = None
        try:
            container = self._client.containers.run(
                self.image,
                command=["--workspace", "/workspace"],
                mounts=mounts,
                environment=env_vars,
                network_mode=self.network_mode,
                mem_limit="1g",
                cpu_quota=100000,   # 1 full core
                pids_limit=200,
                detach=True,
            )
            container.wait(timeout=self.timeout)
            logs = container.logs().decode("utf-8", errors="replace")
            return {"logs": logs}

        except Exception as e:
            return {"logs": f"Container error: {e}"}
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Trace reconstruction
    # ------------------------------------------------------------------

    def _populate_collector(self, data: dict, collector: TraceCollector) -> None:
        """Reconstruct TraceCollector steps from container output.json."""
        for step in data.get("trace_steps", []):
            file_ops = [
                FileOperation(
                    operation=op.get("operation", "read"),
                    path=op.get("path", ""),
                    content=None,
                    success=True,
                )
                for op in step.get("file_operations", [])
            ]
            net_calls = [
                NetworkCall(
                    method=nc.get("method", "GET"),
                    url=nc.get("url", ""),
                    headers={},
                    body=nc.get("body"),
                    response_status=None,
                    response_body=None,
                )
                for nc in step.get("network_calls", [])
            ]
            collector.add_skill_call(
                skill_name=step["skill_name"],
                input_params=step.get("input_params", {}),
                output=step.get("output", {}),
                declared_permissions=step.get("declared_permissions", []),
                actual_permissions=step.get("actual_permissions", []),
                network_calls=net_calls,
                file_operations=file_ops,
                state_snapshot=step.get("state_snapshot", {}),
            )

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    @classmethod
    def available(cls) -> bool:
        if not _DOCKER_AVAILABLE:
            return False
        try:
            client = docker.from_env()
            client.images.get(IMAGE_NAME)
            return True
        except Exception:
            return False
