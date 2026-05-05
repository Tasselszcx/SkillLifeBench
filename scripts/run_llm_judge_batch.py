"""Batch run LLM Judge with multiple models.

Usage:
    python scripts/run_llm_judge_batch.py
"""

import subprocess
import sys
from pathlib import Path

MODELS = [
    "claude-opus-4-6",
    "gemini-3-flash-preview",
    "deepseek-v3",
    "GLM-4.6",
]

SOURCE = "docker_full_qwen3-32b_120"


def main():
    root = Path(__file__).parent.parent
    script = root / "scripts" / "run_llm_judge.py"

    print(f"Running LLM Judge for {len(MODELS)} models...")
    print(f"Source: {SOURCE}")
    print(f"Models: {', '.join(MODELS)}\n")

    for i, model in enumerate(MODELS, 1):
        print(f"\n{'='*60}")
        print(f"[{i}/{len(MODELS)}] Running LLM Judge with model: {model}")
        print(f"{'='*60}\n")

        cmd = [
            sys.executable,
            str(script),
            "--model", model,
            "--source", SOURCE,
        ]

        try:
            subprocess.run(cmd, check=True, cwd=str(root))
            print(f"\n✓ Completed: {model}")
        except subprocess.CalledProcessError as e:
            print(f"\n✗ Failed: {model} (exit code {e.returncode})")
            print("Continuing with next model...")

    print(f"\n{'='*60}")
    print("Batch run completed!")
    print(f"Results saved to: results/llm_judge_<model>/judge_results.json")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
