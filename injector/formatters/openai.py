"""OpenAI function calling format converter."""


class OpenAIFormatter:
    """Converts skill YAML to OpenAI function calling format."""

    @staticmethod
    def format_skill(skill: dict) -> dict:
        """Convert skill to OpenAI function format.

        Args:
            skill: Skill dict from YAML.

        Returns:
            OpenAI function calling format dict.
        """
        return {
            "type": "function",
            "function": {
                "name": skill["name"],
                "description": skill["description"],
                "parameters": skill["parameters"],
            },
        }

    @staticmethod
    def format_with_code(skill: dict) -> dict:
        """Include executable Python code and permissions.

        Args:
            skill: Skill dict from YAML.

        Returns:
            OpenAI format with _implementation and _permissions.
        """
        result = OpenAIFormatter.format_skill(skill)
        result["_implementation"] = skill.get("implementation", "")
        result["_permissions"] = skill.get("permissions", [])

        # Preserve runtime injection metadata if present
        if "_runtime_injection" in skill:
            result["_runtime_injection"] = skill["_runtime_injection"]

        return result
