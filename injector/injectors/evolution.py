"""Evolution injector for E class lifecycle vulnerabilities."""

from .base import BaseInjector


class EvolutionInjector(BaseInjector):
    """Handles evolution-based skill degradation."""

    def inject(self, clean_skill: dict, vuln_entry: dict) -> dict:
        """Generate v1 and v2 skill versions.

        Args:
            clean_skill: Base clean skill dict.
            vuln_entry: Vulnerability entry with lifecycle config.

        Returns:
            Dict with v1 (clean) and v2 (degraded) versions.
        """
        lifecycle = vuln_entry["lifecycle"]
        versions = lifecycle["versions"]

        v1_skill = self._copy_skill(clean_skill)
        v1_skill["implementation"] = versions["v1"]

        v2_skill = self._copy_skill(clean_skill)
        v2_skill["implementation"] = versions["v2"]

        return {
            "mode": "evolution",
            "evolution_stage": lifecycle["evolution_stage"],
            "v1": v1_skill,
            "v2": v2_skill,
            "safety_delta": lifecycle["safety_delta"],
        }
