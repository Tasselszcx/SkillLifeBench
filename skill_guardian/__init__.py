"""skill_guardian — Skill Guardian middleware for SafeBench.

Three-layer defense middleware that intercepts skill execution at:
  L1 (Acquire Gate)  — static scan before writing impl_code to disk
  L2 (Invoke Gate)   — runtime check before fn(**kwargs) executes
  L3 (Response Gate) — runtime check after fn(**kwargs) returns
"""

from .core import GuardianResult, SkillGuardian

__all__ = ["GuardianResult", "SkillGuardian"]
