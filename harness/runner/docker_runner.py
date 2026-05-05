"""Docker-isolated agent runner base class."""

import json
import tempfile
from pathlib import Path
from typing import Any

try:
    import docker
    from docker.types import Mount
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

from .base import AgentRunner, RunResult
from ..collector.trace_collector import TraceCollector


class DockerRunner(AgentRunner):
    """Base class for Docker-isolated agent execution."""

    def __init__(
        self,
        image: str = "safebench-sandbox:latest",
        timeout: int = 60,
        memory_limit: str = "512m",
        cpu_quota: int = 50000,
        network_mode: str = "none",
    ):
        if not DOCKER_AVAILABLE:
            raise ImportError("docker package required. Install: pip install docker")

        self.image = image
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.cpu_quota = cpu_quota
        self.network_mode = network_mode
        self.client = docker.from_env()

    def run(
        self,
        injected_package: dict,
        collector: TraceCollector,
    ) -> RunResult:
        """Execute in isolated Docker container."""

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)

            # Write input
            input_file = tmp_path / "input.json"
            input_file.write_text(json.dumps(injected_package), encoding="utf-8")

            output_file = tmp_path / "output.json"

            try:
                container = self.client.containers.run(
                    self.image,
                    command=["--input", "/workspace/input.json", "--output", "/workspace/output.json"],
                    mounts=[Mount("/workspace", str(tmp_path), type="bind", read_only=False)],
                    network_mode=self.network_mode,
                    mem_limit=self.memory_limit,
                    cpu_quota=self.cpu_quota,
                    pids_limit=100,
                    read_only=True,
                    tmpfs={"/tmp": "size=100m,mode=1777"},
                    security_opt=["no-new-privileges"],
                    cap_drop=["ALL"],
                    detach=True,
                )

                # Wait with timeout
                result = container.wait(timeout=self.timeout)
                logs = container.logs().decode("utf-8")

                # Read results
                if output_file.exists():
                    output_data = json.loads(output_file.read_text(encoding="utf-8"))
                    self._populate_collector(output_data, collector)

                    return RunResult(
                        task_completed=output_data.get("task_completed", False),
                        final_output=output_data.get("final_output", ""),
                        metadata={"container_logs": logs}
                    )
                else:
                    return RunResult(
                        task_completed=False,
                        final_output="",
                        error="Container produced no output",
                        metadata={"container_logs": logs}
                    )

            except Exception as e:
                return RunResult(
                    task_completed=False,
                    final_output="",
                    error=f"Execution error: {e}",
                )
            finally:
                try:
                    container.remove(force=True)
                except:
                    pass

    def _populate_collector(self, output_data: dict, collector: TraceCollector):
        """Reconstruct TraceCollector from container output."""
        for step in output_data.get("trace_steps", []):
            collector.add_skill_call(
                skill_name=step["skill_name"],
                input_params=step["input_params"],
                output=step["output"],
                declared_permissions=step["declared_permissions"],
                actual_permissions=step["actual_permissions"],
                network_calls=step.get("network_calls", []),
                file_operations=step.get("file_operations", []),
                state_snapshot=step.get("state_snapshot", {}),
            )
