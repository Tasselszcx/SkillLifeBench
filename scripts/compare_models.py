"""Compare different models' security awareness using DynamicBehaviorDetector."""
import os
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from harness.pipeline import EvalPipeline
from harness.runner.langchain_runner import LangChainRunner

# API configuration — set OPENAI_API_KEY and OPENAI_BASE_URL in your .env file

# Models to test
MODELS = [
    "gpt-4o-mini",
    "gpt-4o",
    "gpt-3.5-turbo",
]

def run_model_comparison(classes=["A"], limit=20):
    """Run evaluation on multiple models and compare results."""
    results = {}

    for model in MODELS:
        print(f"\n{'='*60}")
        print(f"Testing model: {model}")
        print(f"{'='*60}")

        try:
            runner = LangChainRunner("openai", model)
            pipeline = EvalPipeline(
                registry_dir="registry_expanded",
                skills_dir="skills",
                runner=runner,
                framework_name="langchain",
                llm_backend="openai"
            )

            # Get limited vuln_ids
            all_ids = pipeline._collect_vuln_ids(classes)
            vuln_ids = all_ids[:limit] if limit else all_ids

            print(f"Evaluating {len(vuln_ids)} samples...")
            batch_result = pipeline.run_batch(vuln_ids=vuln_ids, verbose=False)

            # Extract key metrics
            scores = batch_result["score_card"]
            by_predicate = scores.get("by_predicate", {})

            results[model] = {
                "total": len(vuln_ids),
                "asr": scores.get("asr", 0),
                "dynamic_behavior": by_predicate.get("DynamicBehavior", {}).get("count", 0),
                "evo_regress": by_predicate.get("EvoRegress", {}).get("count", 0),
                "perm_violation": by_predicate.get("PermViolation", {}).get("count", 0),
                "predicates": by_predicate,
            }

            print(f"\nResults for {model}:")
            print(f"  ASR: {results[model]['asr']:.1%}")
            print(f"  DynamicBehavior: {results[model]['dynamic_behavior']}")
            print(f"  EvoRegress: {results[model]['evo_regress']}")

        except Exception as e:
            print(f"Error testing {model}: {e}")
            results[model] = {"error": str(e)}

    return results

if __name__ == "__main__":
    print("=== Model Security Comparison ===")
    print("Testing models on A-class vulnerabilities (first 20 samples)")

    results = run_model_comparison(classes=["A"], limit=20)

    # Print comparison table
    print(f"\n{'='*80}")
    print("COMPARISON SUMMARY")
    print(f"{'='*80}")
    print(f"{'Model':<20} {'ASR':<10} {'Dynamic':<10} {'EvoRegress':<12} {'PermViol':<10}")
    print(f"{'-'*80}")

    for model, data in results.items():
        if "error" in data:
            print(f"{model:<20} ERROR: {data['error'][:40]}")
        else:
            print(f"{model:<20} {data['asr']:<10.1%} {data['dynamic_behavior']:<10} "
                  f"{data['evo_regress']:<12} {data.get('perm_violation', 0):<10}")

    # Save results
    output_file = "results/model_comparison.json"
    Path("results").mkdir(exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\nDetailed results saved to: {output_file}")
