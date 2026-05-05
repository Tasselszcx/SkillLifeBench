"""DockerSkillExecutor — runs a single skill function inside a Docker sandbox.

Usage:
    executor = DockerSkillExecutor()
    result = executor.execute(
        skill_name="format_date",
        impl_code="def format_date(date_str): return date_str",
        input_params={"date_str": "2026-03-07"},
    )
    print(result.output)        # return value
    print(result.file_ops)      # list of file operations observed
    print(result.network_calls) # list of network calls observed
    print(result.error)         # None if successful
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import docker
    from docker.types import Mount
    _DOCKER_AVAILABLE = True
except ImportError:
    _DOCKER_AVAILABLE = False


IMAGE_NAME = "safebench-sandbox:latest"
DEFAULT_TIMEOUT = 30          # seconds
DEFAULT_MEMORY = "256m"
DEFAULT_CPU_QUOTA = 50000     # 50% of one core


@dataclass
class SkillExecResult:
    output: Any
    file_ops: list[dict] = field(default_factory=list)
    network_calls: list[dict] = field(default_factory=list)
    error: str | None = None
    container_logs: str = ""

    @property
    def succeeded(self) -> bool:
        return self.error is None


class DockerSkillExecutor:
    """Executes a skill's impl_code inside an isolated Docker container.

    The container receives a JSON payload and writes back a JSON result.
    The host LangChain agent is not involved — this is pure skill isolation.

    Args:
        image: Docker image name (must be built with scripts/build_docker.sh).
        timeout: Max seconds to wait for container exit.
        memory_limit: Docker memory limit string (e.g. "256m").
        cpu_quota: Docker CPU quota (50000 = 50% of one core).
        network_mode: "none" for fully isolated (A/B/E class),
                      "bridge" for C/D class exfiltration tests.
    """

    def __init__(
        self,
        image: str = IMAGE_NAME,
        timeout: int = DEFAULT_TIMEOUT,
        memory_limit: str = DEFAULT_MEMORY,
        cpu_quota: int = DEFAULT_CPU_QUOTA,
        network_mode: str = "none",
    ):
        if not _DOCKER_AVAILABLE:
            raise ImportError(
                "docker package not installed. Run: pip install docker"
            )
        self.image = image
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.cpu_quota = cpu_quota
        self.network_mode = network_mode
        self._client = docker.from_env()

    # ------------------------------------------------------------------

    def execute(
        self,
        skill_name: str,
        impl_code: str,
        input_params: dict[str, Any],
    ) -> SkillExecResult:
        """Execute skill in Docker and return structured result."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)

            # Write input
            payload = {
                "skill_name": skill_name,
                "impl_code": impl_code,
                "input_params": input_params,
            }
            (tmp / "input.json").write_text(
                json.dumps(payload, ensure_ascii=False), encoding="utf-8"
            )

            container = None
            try:
                container = self._client.containers.run(
                    self.image,
                    command=[
                        "--input", "/workspace/input.json",
                        "--output", "/workspace/output.json",
                    ],
                    mounts=[Mount("/workspace", str(tmp), type="bind")],
                    network_mode=self.network_mode,
                    mem_limit=self.memory_limit,
                    cpu_quota=self.cpu_quota,
                    pids_limit=50,
                    read_only=True,
                    tmpfs={"/tmp": "size=64m,mode=1777"},
                    security_opt=["no-new-privileges"],
                    cap_drop=["ALL"],
                    detach=True,
                )

                exit_status = container.wait(timeout=self.timeout)
                logs = container.logs().decode("utf-8", errors="replace")

                output_file = tmp / "output.json"
                if output_file.exists():
                    data = json.loads(output_file.read_text(encoding="utf-8"))
                    return SkillExecResult(
                        output=data.get("output"),
                        file_ops=data.get("file_ops", []),
                        network_calls=data.get("network_calls", []),
                        error=data.get("error"),
                        container_logs=logs,
                    )
                else:
                    return SkillExecResult(
                        output=None,
                        error="Container produced no output.json",
                        container_logs=logs,
                    )

            except Exception as e:
                return SkillExecResult(
                    output=None,
                    error=f"Docker execution error: {e}",
                )
            finally:
                if container is not None:
                    try:
                        container.remove(force=True)
                    except Exception:
                        pass

    # ------------------------------------------------------------------

    @classmethod
    def available(cls) -> bool:
        """Return True if Docker is reachable and the sandbox image exists."""
        if not _DOCKER_AVAILABLE:
            return False
        try:
            client = docker.from_env()
            client.images.get(IMAGE_NAME)
            return True
        except Exception:
            return False
