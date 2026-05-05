"""Report generator — produces JSON and Markdown evaluation reports."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from .scorer import ScoreCard


class ReportGenerator:
    """Generates evaluation reports in JSON and Markdown formats."""

    def generate_json(
        self,
        score_card: ScoreCard,
        oracle_results: list[dict],
        metadata: dict | None = None,
    ) -> str:
        """Generate a JSON evaluation report.

        Args:
            score_card: Computed evaluation scores.
            oracle_results: List of per-entry OracleResult dicts.
            metadata: Optional experiment metadata.

        Returns:
            JSON string of the full report.
        """
        report = {
            "report_type": "safebench_evaluation",
            "generated_at": datetime.now().isoformat(),
            "metadata": metadata or {},
            "scores": score_card.to_dict(),
            "total_entries": len(oracle_results),
            "breached_entries": sum(
                1 for r in oracle_results if r["is_breached"]
            ),
            "results": oracle_results,
        }
        return json.dumps(report, indent=2, ensure_ascii=False)

    def generate_markdown(
        self,
        score_card: ScoreCard,
        oracle_results: list[dict],
        metadata: dict | None = None,
    ) -> str:
        """Generate a Markdown evaluation report.

        Args:
            score_card: Computed evaluation scores.
            oracle_results: List of per-entry OracleResult dicts.
            metadata: Optional experiment metadata.

        Returns:
            Markdown string of the report.
        """
        lines = []
        meta = metadata or {}

        lines.append("# SafeBench Evaluation Report\n")
        lines.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        if meta.get("agent_framework"):
            lines.append(f"**Agent Framework**: {meta['agent_framework']}")
        if meta.get("llm_backend"):
            lines.append(f"**LLM Backend**: {meta['llm_backend']}")
        lines.append("")

        # Summary
        total = len(oracle_results)
        breached = sum(1 for r in oracle_results if r["is_breached"])
        lines.append("## Summary\n")
        lines.append(f"- **Total evaluated**: {total}")
        lines.append(f"- **Breached**: {breached}")
        lines.append(f"- **ASR**: {score_card.asr:.1%}")
        lines.append(f"- **DDR**: {score_card.ddr:.1%}")
        lines.append(f"- **SafeScore**: {score_card.safe_score:.3f}")
        lines.append("")

        # Security metrics table
        lines.append("## Security Metrics\n")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| ASR (Attack Success Rate) | {score_card.asr:.1%} |")
        lines.append(f"| DDR (Defense Detection Rate) | {score_card.ddr:.1%} |")
        lines.append(f"| BPR (Block Prevention Rate) | {score_card.bpr:.1%} |")
        lines.append(f"| FSS (Failure Severity Score) | {score_card.fss:.2f} |")
        lines.append("")

        # Utility metrics
        if score_card.tcr > 0:
            lines.append("## Utility Metrics\n")
            lines.append("| Metric | Value |")
            lines.append("|--------|-------|")
            lines.append(f"| TCR (Task Completion Rate) | {score_card.tcr:.1%} |")
            lines.append(f"| TCA (Completion under Attack) | {score_card.tca:.1%} |")
            lines.append(f"| UR (Utility Retention) | {score_card.ur:.1%} |")
            lines.append("")

        # Breakdown by class
        if score_card.by_class:
            lines.append("## ASR by Vulnerability Class\n")
            lines.append("| Class | Total | Breached | ASR |")
            lines.append("|-------|-------|----------|-----|")
            class_names = {"A": "Code-Level", "B": "Interface", "C": "Runtime",
                           "D": "Compositional", "E": "Lifecycle"}
            for cls, data in sorted(score_card.by_class.items()):
                name = class_names.get(cls, cls)
                lines.append(
                    f"| {cls} ({name}) | {data['total']} | "
                    f"{data['breached']} | {data['asr']:.0%} |"
                )
            lines.append("")

        # Breakdown by subclass
        if score_card.by_subclass:
            lines.append("## ASR by Subclass\n")
            lines.append("| Subclass | Total | Breached | ASR |")
            lines.append("|----------|-------|----------|-----|")
            for sub, data in sorted(score_card.by_subclass.items()):
                lines.append(
                    f"| {sub} | {data['total']} | "
                    f"{data['breached']} | {data['asr']:.0%} |"
                )
            lines.append("")

        # Predicate breakdown
        if score_card.by_predicate:
            lines.append("## Breach Predicate Trigger Rates\n")
            lines.append("| Predicate | Count | Rate |")
            lines.append("|-----------|-------|------|")
            for pred, data in sorted(score_card.by_predicate.items()):
                lines.append(
                    f"| {pred} | {data['count']} | {data['rate']:.0%} |"
                )
            lines.append("")

        # Detailed results
        lines.append("## Detailed Results\n")
        for r in oracle_results:
            status = "BREACH" if r["is_breached"] else "SAFE"
            icon = "x" if r["is_breached"] else "v"
            lines.append(f"### [{icon}] {r['vuln_id']} — {status}\n")
            lines.append(f"- **Severity**: {r['max_severity']}")
            lines.append(
                f"- **Predicates**: {', '.join(r.get('predicates_triggered', []))}"
            )
            if r.get("breaches"):
                lines.append(f"- **Breach count**: {r['breach_count']}")
                for b in r["breaches"][:5]:  # Show max 5
                    lines.append(
                        f"  - [{b['predicate']}] {b['evidence'][:200]}"
                    )
            lines.append("")

        lines.append("---\n")
        lines.append("*Generated by SafeBench Safety Oracle*\n")

        return "\n".join(lines)
