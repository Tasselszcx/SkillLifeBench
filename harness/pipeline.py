"""EvalPipeline — orchestrates the full evaluation flow."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from injector.engine import InjectionEngine
from oracle.oracle import SafetyOracle
from oracle.scorer import Scorer
from oracle.report import ReportGenerator

from harness.collector.trace_collector import TraceCollector
from harness.runner.base import AgentRunner
from harness.runner.mock_runner import MockRunner


class EvalPipeline:
    """End-to-end evaluation pipeline.

    Connects Registry → InjectionEngine → AgentRunner → TraceCollector
    → SafetyOracle → Scorer → ReportGenerator.
    """

    def __init__(
        self,
        registry_dir: str | Path,
        skills_dir: str | Path,
        runner: AgentRunner | None = None,
        framework_name: str = "mock",
        llm_backend: str = "none",
        isolation_mode: str = "none",
        use_guardian: bool = False,
        guardian_layers: list[str] | None = None,
    ):
        self.registry_dir = Path(registry_dir)
        self.skills_dir = Path(skills_dir)
        self.engine = InjectionEngine(self.registry_dir, self.skills_dir)
        self.oracle = SafetyOracle()
        self.scorer = Scorer()
        self.report_gen = ReportGenerator()

        # Auto-select runner based on isolation mode
        if runner is None:
            if isolation_mode == "docker":
                from harness.runner.task_docker_runner import TaskDockerRunner
                self.runner = TaskDockerRunner(
                    llm_backend=llm_backend,
                    model=framework_name if framework_name != "mock" else "gpt-4o-mini",
                    use_guardian=use_guardian,
                    guardian_layers=guardian_layers,
                )
            elif isolation_mode == "llm_judge":
                from harness.runner.llm_judge_runner import LLMJudgeRunner
                self.runner = LLMJudgeRunner(
                    model=framework_name if framework_name != "mock" else "gpt-4o",
                )
            elif isolation_mode == "none" and llm_backend != "none":
                from harness.runner.langchain_runner import LangChainRunner
                self.runner = LangChainRunner(llm_backend=llm_backend)
            else:
                self.runner = MockRunner()
        else:
            self.runner = runner

        self.framework_name = framework_name
        self.llm_backend = llm_backend
        self.isolation_mode = isolation_mode

    # ------------------------------------------------------------------
    # Single vulnerability evaluation
    # ------------------------------------------------------------------

    def run_single(self, vuln_id: str, verbose: bool = False) -> dict:
        """Evaluate one vulnerability entry end-to-end.

        Returns:
            Dict with oracle_result, run_result, and vuln metadata.
        """
        # 1. Load vuln entry
        vuln_entry = self.engine.load_vulnerability(vuln_id)

        # 2. Generate injected skill package
        injected_package = self.engine.generate_injected_skill(vuln_id)

        # 3. Create trace collector
        task_desc = vuln_entry.get("evaluation", {}).get("task_description", "")
        collector = TraceCollector(
            trace_id=f"eval-{vuln_id}",
            vuln_id=vuln_id,
            framework=self.framework_name,
            llm_backend=self.llm_backend,
            task_description=task_desc,
        )

        # 4. Run agent
        run_result = self.runner.run(injected_package, collector)

        # 5. Finalize trace
        trace = collector.finalize(run_result.final_output)

        # 6. Oracle evaluate
        llm_decision = None
        if self.isolation_mode == "llm_judge" and run_result.metadata:
            llm_decision = run_result.metadata.get("llm_decision", "USE")

        oracle_result = self.oracle.evaluate(trace, vuln_entry, llm_decision=llm_decision)

        if verbose:
            status = "BREACH" if oracle_result.is_breached else "SAFE"
            dec = f" | llm={llm_decision}" if llm_decision else ""
            print(f"  [{vuln_id}] {status} | severity={oracle_result.max_severity}"
               f" | breaches={oracle_result.breach_count}"
                  f" | predicates={sorted(oracle_result.predicates_triggered)}"
                  f"{dec}")

        # 7. Return combined result
        result = oracle_result.to_dict()
        result["task_completed"] = run_result.task_completed
        result["final_output"] = run_result.final_output
        if run_result.metadata:
            result["llm_decision"] = run_result.metadata.get("llm_decision")
            result["llm_reason"] = run_result.metadata.get("llm_reason")
        return result

    # ------------------------------------------------------------------
    # Batch evaluation
    # ------------------------------------------------------------------

    def run_batch(
        self,
        vuln_ids: list[str] | None = None,
        classes: list[str] | None = None,
        verbose: bool = False,
    ) -> dict[str, Any]:
        """Evaluate multiple vulnerabilities.

        Args:
            vuln_ids: Specific vuln IDs to evaluate. If None, use classes.
            classes: Vulnerability classes to include (e.g., ["A","B","C"]).
                     If both None, evaluates all.
            verbose: Print per-entry results.

        Returns:
            Dict with score_card, results list, and report strings.
        """
        if vuln_ids is None:
            vuln_ids = self._collect_vuln_ids(classes)

        total = len(vuln_ids)
        if verbose:
            print(f"Running evaluation on {total} entries...")

        results: list[dict] = []
        errors: list[dict] = []

        for idx, vuln_id in enumerate(vuln_ids, 1):
            try:
                result = self.run_single(vuln_id, verbose=verbose)
                results.append(result)
            except Exception as e:
                errors.append({"vuln_id": vuln_id, "error": str(e)})
                if verbose:
                    print(f"  [{vuln_id}] ERROR: {e}")

            # Progress line (always shown, overwrites same line)
            breached_so_far = sum(1 for r in results if r.get("is_breached"))
            idx_filled = len(results) + len(errors)
            asr = breached_so_far / idx_filled if idx_filled > 0 else 0
            print(f"\r  Progress: {idx}/{total}  ASR so far: {breached_so_far}/{idx_filled} ({asr:.0%})   ",
                  end="", flush=True)

        # Score
        score_card = self.scorer.score(results)

        # Reports
        metadata = {
            "agent_framework": self.framework_name,
            "llm_backend": self.llm_backend,
            "total_entries": len(vuln_ids),
            "errors": len(errors),
        }
        report_json = self.report_gen.generate_json(score_card, results, metadata)
        report_md = self.report_gen.generate_markdown(score_card, results, metadata)

        return {
            "score_card": score_card.to_dict(),
            "results": results,
            "errors": errors,
            "report_json": report_json,
            "report_md": report_md,
        }

    def run_all(self, verbose: bool = False) -> dict[str, Any]:
        """Evaluate all vulnerabilities in the registry."""
        return self.run_batch(vuln_ids=None, classes=None, verbose=verbose)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _collect_vuln_ids(
        self, classes: list[str] | None = None
    ) -> list[str]:
        """Collect all vuln IDs from registry, optionally filtered by class."""
        yaml_files = sorted(self.registry_dir.rglob("*.yaml"))
        vuln_ids = []

        for yf in yaml_files:
            with open(yf, "r", encoding="utf-8") as f:
                entry = yaml.safe_load(f)
            vid = entry.get("vuln_id", "")
            if not vid:
                continue
            if classes is not None:
                entry_class = entry.get("class", "")
                if entry_class not in classes:
                    continue
            vuln_ids.append(vid)

        return vuln_ids

    # ------------------------------------------------------------------
    # Save results to disk
    # ------------------------------------------------------------------

    def save_results(
        self, batch_result: dict[str, Any], output_dir: str | Path
    ) -> None:
        """Save report.json and report.md to output directory."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        json_path = out / "report.json"
        md_path = out / "report.md"

        json_path.write_text(batch_result["report_json"], encoding="utf-8")
        md_path.write_text(batch_result["report_md"], encoding="utf-8")

        print(f"Reports saved to {out}/")
        print(f"  - {json_path}")
        print(f"  - {md_path}")
