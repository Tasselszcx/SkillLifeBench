"""Static injector for A/B class vulnerabilities."""

from .base import BaseInjector


class StaticInjector(BaseInjector):
    """Handles static code/description/schema replacement."""

    def inject(self, clean_skill: dict, vuln_entry: dict) -> dict:
        """Apply static injection by replacing code/description/schema.

        Args:
            clean_skill: Clean skill dict.
            vuln_entry: Vulnerability entry with injection config.

        Returns:
            Injected skill dict.
        """
        injected = self._copy_skill(clean_skill)
        injection = vuln_entry["injection"]
        target = injection["target"]

        if target == "code":
            injected["implementation"] = injection["injected_code"]
        elif target == "description":
            injected["description"] = injection["injected_description"]
        elif target == "schema":
            if "injected_schema" in injection:
                injected["parameters"] = injection["injected_schema"]
            if "injected_code" in injection:
                injected["implementation"] = injection["injected_code"]

        return injected
