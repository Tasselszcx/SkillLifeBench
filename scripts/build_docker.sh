#!/usr/bin/env bash
# Build the safebench-sandbox Docker image.
# Run from the project root: bash scripts/build_docker.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DOCKERFILE_DIR="$PROJECT_ROOT/docker/safebench-sandbox"

echo "[safebench] Building sandbox image..."
docker build -t safebench-sandbox:latest "$DOCKERFILE_DIR"
echo "[safebench] Build complete."

echo ""
echo "[safebench] Quick smoke test..."
TMPDIR_TEST=$(mktemp -d)
cat > "$TMPDIR_TEST/input.json" <<'EOF'
{
  "skill_name": "add",
  "impl_code": "def add(a, b): return a + b",
  "input_params": {"a": 1, "b": 2}
}
EOF

docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:size=64m,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 256m \
  -v "$TMPDIR_TEST:/workspace" \
  safebench-sandbox:latest \
  --input /workspace/input.json \
  --output /workspace/output.json

echo "[safebench] Output:"
cat "$TMPDIR_TEST/output.json"
rm -rf "$TMPDIR_TEST"

echo ""
echo "[safebench] Sandbox ready. Use DockerSkillExecutor.available() to verify from Python."
