"""Compositional injector for D class skill chains."""

from .base import BaseInjector


class CompositionalInjector(BaseInjector):
    """Handles skill chain composition vulnerabilities."""

    def inject(self, clean_skill: dict, vuln_entry: dict) -> dict:
        """Return skill chain metadata.

        Args:
            clean_skill: Not used for D-class.
            vuln_entry: Vulnerability entry with compositional config.

        Returns:
            Skill chain metadata dict.
        """
        compositional = vuln_entry["compositional"]

        return {
            "mode": "compositional",
            "skill_chain": compositional["skill_chain"],
            "chain_description": compositional["chain_description"],
            "individual_safety": compositional["individual_safety"],
        }
