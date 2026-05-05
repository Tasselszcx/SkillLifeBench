"""
Build the safebench-sandbox Docker image and run a smoke test.
Works on Windows, macOS, and Linux.

Usage:
    python scripts/build_docker.py
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
DOCKERFILE_DIR = PROJECT_ROOT / "docker" / "safebench-sandbox"
IMAGE_NAME = "safebench-sandbox:latest"

DOCKER_BIN = (
    r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"
    if sys.platform == "win32"
    else "docker"
)


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        print(f"ERROR: command exited with {result.returncode}")
        sys.exit(result.returncode)
    return result


def main():
    # 1. Build image
    print("[safebench] Building sandbox image...")
    run([DOCKER_BIN, "build", "-t", IMAGE_NAME, str(DOCKERFILE_DIR)])
    print("[safebench] Build complete.\n")

    # 2. Smoke test — use workspace layout matching entrypoint.py
    print("[safebench] Running smoke test...")

    # Minimal task.json + a trivial skill
    task = {
        "vuln_id": "smoke-test",
        "class": "A",
        "subclass": "A1",
        "task_description": "Call the add skill with a=1 and b=2.",
        "attack_input": "",
        "llm_backend": "none",   # no LLM needed for smoke test
        "model": "none",
    }
    skill_yaml = {
        "name": "add",
        "description": "Add two numbers.",
        "parameters": {"properties": {"a": {}, "b": {}}},
        "permissions": [],
    }
    skill_impl = "def add(a, b):\n    return int(a) + int(b)\n"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "task.json").write_text(json.dumps(task), encoding="utf-8")

        skill_dir = tmp / "skills" / "add"
        skill_dir.mkdir(parents=True)
        import yaml as _yaml
        with open(skill_dir / "skill.yaml", "w", encoding="utf-8") as f:
            _yaml.dump(skill_yaml, f)
        (skill_dir / "implementation.py").write_text(skill_impl, encoding="utf-8")

        mount_src = str(tmp.resolve())

        run([
            DOCKER_BIN, "run", "--rm",
            "--network", "none",
            "--memory", "256m",
            "-v", f"{mount_src}:/workspace",
            IMAGE_NAME,
            "--workspace", "/workspace",
        ])

        output_file = tmp / "output.json"
        if output_file.exists():
            result = json.loads(output_file.read_text(encoding="utf-8"))
            print(f"[safebench] Output: task_completed={result.get('task_completed')}, "
                  f"error={result.get('error')}, steps={len(result.get('trace_steps', []))}")
            if result.get("error") and "no LLM" not in str(result.get("error", "")):
                print(f"[safebench] WARNING: error={result['error']}")
            print("[safebench] Smoke test PASSED.")
        else:
            print("[safebench] ERROR: output.json not found.")
            sys.exit(1)

    print("\n[safebench] Sandbox ready.")


if __name__ == "__main__":
    main()
