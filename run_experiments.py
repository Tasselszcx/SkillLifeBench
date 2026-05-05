"""Multi-model comparison experiments - Docker execution mode, hybrid Oracle v2.

Usage:
    python run_experiments.py                    # run all models
    python run_experiments.py --model GLM-4.6   # run single model
    python run_experiments.py --model GLM-4.6 --classes A,B,C
"""

import argparse
import os
from pathlib import Path

# Load .env if present (no external dependency needed)
_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    for line in _env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

if not os.environ.get("OPENAI_API_KEY"):
    raise EnvironmentError(
        "OPENAI_API_KEY is not set. "
        "Add it to .env or export OPENAI_API_KEY=<your_key> before running."
    )

from harness.pipeline import EvalPipeline

MODELS = ["qwen3-32b", "kimi-k2.5", "deepseek-v3", "GLM-4.6", "gpt-5-mini"]
CLASSES = ["A", "B", "C", "D", "E"]
REGISTRY_DIR = "registry_final"

# Toggle for RQ5 defense experiment.
# False = baseline run (RQ1/2/3).  True = Guardian-enabled run (RQ2).
USE_GUARDIAN = True
GUARDIAN_LAYERS = ["L1", "L2", "L3"]  # Default to all


def run_experiment(model, classes, layers=None):
    print(f"\n{'='*60}")
    print(f"  Testing model: {model}")
    current_layers = layers if layers is not None else GUARDIAN_LAYERS
    if USE_GUARDIAN:
        print(f"  [Guardian] Skill Guardian ENABLED (Layers: {', '.join(current_layers)})")
    print(f"{'='*60}")
    pipeline = EvalPipeline(
        registry_dir=REGISTRY_DIR, skills_dir="skills",
        isolation_mode="docker", llm_backend="openai",
        framework_name=model,
        use_guardian=USE_GUARDIAN,
        guardian_layers=current_layers,
    )
    result = pipeline.run_batch(classes=classes, verbose=True)

    if USE_GUARDIAN:
        layer_tag = "full" if len(current_layers) == 3 else "_".join(current_layers).lower()
        tag = f"guardian_{layer_tag}"
    else:
        tag = "full"

    output_dir = Path("results") / f"docker_{tag}_{model.replace(':', '_')}_120"
    pipeline.save_results(result, output_dir)
    score = result["score_card"]
    sec = score["security"]
    by_class = score.get("by_class", {})
    print(f"\n  {model} Results:")
    print(f"    Overall ASR: {sec['asr']:.1%}  ({score.get('total_breached',0)}/{score.get('total_entries',0)})")
    for cn, cd in sorted(by_class.items()):
        print(f"    {cn}-class ASR: {cd['asr']:.1%} ({cd['breached']}/{cd['total']})")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=None,
                        help="Run a single model (e.g. GLM-4.6). Omit to run all.")
    parser.add_argument("--classes", default=None,
                        help="Comma-separated classes to test, e.g. A,B,C. Default: all.")
    parser.add_argument("--layers", default=None,
                        help="Comma-separated layers to enable, e.g. L1,L2. Default: all.")
    args = parser.parse_args()

    models_to_run = [args.model] if args.model else MODELS
    classes_to_run = args.classes.upper().split(",") if args.classes else CLASSES
    layers_to_run = args.layers.upper().split(",") if args.layers else GUARDIAN_LAYERS

    all_results = {}
    for model in models_to_run:
        try:
            all_results[model] = run_experiment(model, classes_to_run, layers=layers_to_run)
        except Exception as e:
            print(f"\n  ERROR testing {model}: {e}")
            import traceback
            traceback.print_exc()

    if len(all_results) > 1:
        print(f"\n{'='*60}")
        print("  SUMMARY: Model Comparison (Hybrid Oracle v2 — Static+Runtime)")
        print(f"{'='*60}")
        print(f"  {'Model':<20s} {'Overall':>8s} {'A':>7s} {'B':>7s} {'C':>7s} {'D':>7s} {'E':>7s}")
        print(f"  {'-'*20} {'-'*8} {'-'*7} {'-'*7} {'-'*7} {'-'*7} {'-'*7}")
        for model, result in all_results.items():
            score = result["score_card"]
            overall = score["security"]["asr"]
            bc = score.get("by_class", {})
            a = bc.get("A", {}).get("asr", 0)
            b = bc.get("B", {}).get("asr", 0)
            c = bc.get("C", {}).get("asr", 0)
            d = bc.get("D", {}).get("asr", 0)
            e = bc.get("E", {}).get("asr", 0)
            print(f"  {model:<20s} {overall:>7.1%} {a:>6.1%} {b:>6.1%} {c:>6.1%} {d:>6.1%} {e:>6.1%}")
        print(f"\nExpectation: Stronger models -> Lower ASR")

