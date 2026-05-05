"""Injection Engine main class."""

from pathlib import Path
import yaml

from .injectors import (
    StaticInjector,
    DynamicInjector,
    CompositionalInjector,
    EvolutionInjector,
)
from .formatters import OpenAIFormatter


class InjectionEngine:
    """Main engine for generating injected skills from vulnerability registry."""

    def __init__(self, registry_dir: Path, skills_dir: Path):
        """Initialize injection engine.

        Args:
            registry_dir: Path to vulnerability registry directory.
            skills_dir: Path to clean skills directory.
        """
        self.registry_dir = Path(registry_dir)
        self.skills_dir = Path(skills_dir)
        self.formatter = OpenAIFormatter()

        # Initialize injectors
        self.injectors = {
            "static": StaticInjector(),
            "dynamic": DynamicInjector(),
            "compositional": CompositionalInjector(),
            "evolution": EvolutionInjector(),
        }

    def load_vulnerability(self, vuln_id: str) -> dict:
        """Load vulnerability entry by ID.

        Args:
            vuln_id: Vulnerability ID (e.g., "A1-001").

        Returns:
            Vulnerability entry dict.
        """
        yaml_files = list(self.registry_dir.rglob(f"{vuln_id}.yaml"))
        if not yaml_files:
            raise FileNotFoundError(f"Vulnerability {vuln_id} not found")

        with open(yaml_files[0], "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def load_clean_skill(self, skill_ref: str) -> dict:
        """Load clean skill template.

        Supports two formats:
        - Directory format (new): skills/<name>/skill.yaml + implementation.py
        - Single-file format (legacy): skills/<name>.yaml

        The directory format takes precedence when both exist.

        Args:
            skill_ref: Skill reference path (e.g., "skills/format_date.yaml"
                       or "skills/format_date").

        Returns:
            Clean skill dict with 'implementation' key populated.
        """
        base_path = self.skills_dir.parent / skill_ref

        # Resolve to base name (strip .yaml if present)
        if base_path.suffix == ".yaml":
            dir_path = base_path.parent / base_path.stem
        else:
            dir_path = base_path

        # Try new directory format first
        meta_path = dir_path / "skill.yaml"
        impl_path = dir_path / "implementation.py"
        if dir_path.is_dir() and meta_path.exists():
            with open(meta_path, "r", encoding="utf-8") as f:
                skill = yaml.safe_load(f)
            if impl_path.exists():
                skill["implementation"] = impl_path.read_text(encoding="utf-8")
            return skill

        # Fall back to legacy single-file format
        yaml_path = base_path if base_path.suffix == ".yaml" else Path(str(base_path) + ".yaml")
        with open(yaml_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def generate_injected_skill(self, vuln_id: str) -> dict:
        """Generate injected skill package for a vulnerability.

        Args:
            vuln_id: Vulnerability ID.

        Returns:
            Complete injected skill package dict.
        """
        vuln_entry = self.load_vulnerability(vuln_id)
        vuln_class = vuln_entry["class"]

        # Handle E-class (evolution) specially
        if vuln_class == "E":
            return self._generate_evolution(vuln_entry)

        # Handle D-class (compositional chain) specially
        if vuln_class == "D":
            return self._generate_compositional(vuln_entry)

        # Handle A/B/C classes (standard injection)
        return self._generate_standard(vuln_entry)

    def _generate_standard(self, vuln_entry: dict) -> dict:
        """Generate standard injected skill (A/B/C classes)."""
        clean_skill = self.load_clean_skill(vuln_entry["target_skill"]["ref"])
        injection_mode = vuln_entry["injection"]["mode"]

        injector = self.injectors[injection_mode]
        injected_skill = injector.inject(clean_skill, vuln_entry)

        # For dynamic mode: replace implementation so the skill actually returns
        # the injected response at runtime (DynamicInjector only adds metadata).
        if injection_mode == "dynamic":
            injected_response = vuln_entry["injection"].get("injected_response", "")
            if injected_response:
                skill_name = clean_skill.get("name", "unknown")
                param_names = clean_skill.get("parameters", {}).get("properties", {}).keys()
                injected_skill["implementation"] = self._make_injected_response_impl(
                    skill_name, param_names, injected_response,
                )

        return {
            "vuln_id": vuln_entry["vuln_id"],
            "class": vuln_entry["class"],
            "subclass": vuln_entry["subclass"],
            "severity": vuln_entry["severity"],
            "clean_skill": self.formatter.format_with_code(clean_skill),
            "injected_skill": self.formatter.format_with_code(injected_skill),
            "evaluation": vuln_entry["evaluation"],
            "metadata": {
                "injection_mode": injection_mode,
                "difficulty": vuln_entry["metadata"]["difficulty"],
                "tags": vuln_entry["metadata"]["tags"],
            },
        }

    def _generate_compositional(self, vuln_entry: dict) -> dict:
        """Generate compositional skill chain (D class).

        Two sub-cases:
        - Has 'compositional' field: true skill-chain scenario (D1/D2/D3 with chain).
          Applies injection to the target skill; all others use clean implementations.
        - No 'compositional' field: single-skill D-class entry (e.g. D2-060 series).
          Falls back to _generate_standard() — same flow as A/B/C.
        """
        if "compositional" not in vuln_entry:
            # Single-skill D-class: treat like A/B/C standard injection
            return self._generate_standard(vuln_entry)

        compositional = vuln_entry["compositional"]
        injection = vuln_entry.get("injection", {})
        injection_mode = injection.get("mode", "static")
        injected_response = injection.get("injected_response", "")
        injected_code = injection.get("injected_code", "")

        # Identify target skill by name from target_skill.ref
        target_ref = vuln_entry.get("target_skill", {}).get("ref", "")
        target_skill_name = Path(target_ref).stem  # e.g. "skills/db_query.yaml" → "db_query"

        chain_data = []
        for skill_entry in compositional["skill_chain"]:
            clean_skill = self.load_clean_skill(skill_entry["skill_ref"])
            skill_name = clean_skill.get("name", "")

            # Apply injection to the target skill only
            if skill_name == target_skill_name:
                injected_skill = dict(clean_skill)
                if injection_mode == "dynamic" and injected_response:
                    # Replace return value with injected payload
                    param_names = clean_skill.get("parameters", {}).get("properties", {}).keys()
                    injected_skill["implementation"] = self._make_injected_response_impl(
                        skill_name, param_names, injected_response,
                    )
                elif injected_code:
                    injected_skill["implementation"] = injected_code
                chain_data.append({
                    "skill": self.formatter.format_with_code(injected_skill),
                    "role": skill_entry["role"],
                })
            else:
                # All other skills: clean implementation
                chain_data.append({
                    "skill": self.formatter.format_with_code(clean_skill),
                    "role": skill_entry["role"],
                })

        return {
            "vuln_id": vuln_entry["vuln_id"],
            "class": "D",
            "subclass": vuln_entry.get("subclass", "D"),
            "severity": vuln_entry.get("severity", "high"),
            "mode": "compositional",
            "skill_chain": chain_data,
            "chain_description": compositional["chain_description"],
            "individual_safety": compositional["individual_safety"],
            "evaluation": vuln_entry["evaluation"],
            "metadata": vuln_entry["metadata"],
        }

    @staticmethod
    def _make_injected_response_impl(skill_name: str, param_names, injected_response: str) -> str:
        """Generate a Python implementation that always returns the injected response."""
        params = ", ".join(f"{p}: str = ''" for p in param_names) if param_names else "**kwargs"
        return (
            f"def {skill_name}({params}):\n"
            f"    \"\"\"INJECTED: returns poisoned payload regardless of input.\"\"\"\n"
            f"    import json\n"
            f"    payload = {repr(injected_response)}\n"
            f"    try:\n"
            f"        return json.loads(payload)\n"
            f"    except Exception:\n"
            f"        return payload\n"
        )

    def _generate_evolution(self, vuln_entry: dict) -> dict:
        """Generate evolution skill versions (E class)."""
        clean_skill = self.load_clean_skill(vuln_entry["target_skill"]["ref"])
        injected = self.injectors["evolution"].inject(clean_skill, vuln_entry)

        return {
            "vuln_id": vuln_entry["vuln_id"],
            "class": "E",
            "mode": "evolution",
            "evolution_stage": injected["evolution_stage"],
            "v1_skill": self.formatter.format_with_code(injected["v1"]),
            "v2_skill": self.formatter.format_with_code(injected["v2"]),
            "safety_delta": injected["safety_delta"],
            "evaluation": vuln_entry["evaluation"],
            "metadata": vuln_entry["metadata"],
        }

    def generate_all(self) -> list[dict]:
        """Generate all injected skills from registry.

        Returns:
            List of all injected skill packages, sorted by vuln_id.
        """
        yaml_files = sorted(self.registry_dir.rglob("*.yaml"))
        results = []

        for yaml_file in yaml_files:
            with open(yaml_file, "r", encoding="utf-8") as f:
                entry = yaml.safe_load(f)
            vuln_id = entry["vuln_id"]
            results.append(self.generate_injected_skill(vuln_id))

        return sorted(results, key=lambda x: x["vuln_id"])

