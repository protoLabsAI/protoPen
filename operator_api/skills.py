"""Skills browse for the operator console (the memory layer of the control stack).

Skills are retrieved methodology (`SKILL.md` files + agent-emitted skills) injected
into turns by `KnowledgeMiddleware` — see the
[control stack](../docs/explanation/control-stack.md). Operators had no way to see
what's in `skills.db`; this exposes a read-only browse/search over the index.
"""

from __future__ import annotations

from typing import Any


def list_skills_for_console(skills_index: Any, query: str = "") -> dict[str, Any]:
    """List/search skills: name, description, declared tools, source (disk vs
    emitted). Tolerant of a missing index (skills disabled) → empty + disabled."""
    if skills_index is None:
        return {"enabled": False, "count": 0, "skills": []}
    skills = skills_index.all_skills(query or "")
    return {"enabled": True, "count": len(skills), "skills": skills}
