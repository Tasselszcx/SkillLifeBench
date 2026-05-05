"""Dynamic injector for C class runtime vulnerabilities."""

from .base import BaseInjector


class DynamicInjector(BaseInjector):
    """Handles runtime API response interception."""

    def inject(self, clean_skill: dict, vuln_entry: dict) -> dict:
        """Add runtime injection metadata without modifying skill code.

        Args:
            clean_skill: Clean skill dict.
            vuln_entry: Vulnerability entry with injection config.

        Returns:
            Skill with _runtime_injection metadata.
        """
        injected = self._copy_skill(clean_skill)
        injection = vuln_entry["injection"]

        injected["_runtime_injection"] = {
            "mode": "dynamic",
            "target": injection["target"],
            "clean_response": injection.get("clean_response"),
            "injected_response": injection.get("injected_response"),
        }

        return injected
