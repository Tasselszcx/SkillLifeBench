#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Framework Security Profiler - Tests framework-native security features."""

from dataclasses import dataclass
from typing import Dict
import pandas as pd


@dataclass
class SecurityProfile:
    """Security profile for a framework."""
    framework: str
    results: Dict[str, Dict[str, bool]]
    total_features: int
    maturity_level: int

    def __str__(self):
        return f"{self.framework}: {self.total_features}/15 features (L{self.maturity_level})"


class FrameworkSecurityProfiler:
    """Profiles framework security capabilities across 3 dimensions."""

    def __init__(self):
        self.frameworks = ["langchain", "langgraph", "semantic-kernel", "autogen", "crewai"]
        # Import test suites lazily to avoid circular imports
        from harness.profiler.input_validation_tests import InputValidationTests
        from harness.profiler.execution_isolation_tests import ExecutionIsolationTests
        from harness.profiler.observability_tests import ObservabilityTests

        self.dimensions = {
            "input_validation": InputValidationTests(),
            "execution_isolation": ExecutionIsolationTests(),
            "observability": ObservabilityTests()
        }

    def profile_framework(self, framework_name: str) -> SecurityProfile:
        """Test one framework across 3 dimensions."""
        results = {}
        for dim_name, test_suite in self.dimensions.items():
            results[dim_name] = test_suite.run(framework_name)

        total_features = sum(sum(r.values()) for r in results.values())
        maturity_level = self._classify_maturity(results, total_features)

        return SecurityProfile(
            framework=framework_name,
            results=results,
            total_features=total_features,
            maturity_level=maturity_level
        )

    def _classify_maturity(self, results: dict, total: int) -> int:
        """Classify framework maturity level."""
        if total <= 2:
            return 0
        elif total <= 5:
            return 1
        elif total <= 10:
            return 2
        else:
            return 3

    def profile_all(self) -> Dict[str, SecurityProfile]:
        """Profile all frameworks."""
        return {fw: self.profile_framework(fw) for fw in self.frameworks}

    def generate_comparison_table(self) -> pd.DataFrame:
        """Generate framework × feature matrix."""
        profiles = self.profile_all()

        rows = []
        for fw_name, profile in profiles.items():
            row = {"Framework": fw_name}
            for dim_name, features in profile.results.items():
                for feat_name, has_feature in features.items():
                    col_name = f"{dim_name}_{feat_name}"
                    row[col_name] = "✅" if has_feature else "❌"
            row["Total"] = f"{profile.total_features}/15"
            row["Level"] = f"L{profile.maturity_level}"
            rows.append(row)

        return pd.DataFrame(rows)
