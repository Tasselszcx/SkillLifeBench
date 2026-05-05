"""Base injector class."""

from abc import ABC, abstractmethod
import copy


class BaseInjector(ABC):
    """Abstract base class for vulnerability injectors."""

    @abstractmethod
    def inject(self, clean_skill: dict, vuln_entry: dict) -> dict:
        """Apply injection to clean skill.

        Args:
            clean_skill: Clean skill dict from YAML.
            vuln_entry: Vulnerability entry dict from registry.

        Returns:
            Injected skill dict or injection metadata.
        """

    def _copy_skill(self, skill: dict) -> dict:
        """Deep copy to avoid mutation."""
        return copy.deepcopy(skill)
