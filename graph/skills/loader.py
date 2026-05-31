"""Load human-authored skills in the AgentSkills ``SKILL.md`` format.

A skill is a folder containing a ``SKILL.md``: YAML frontmatter (``name`` +
``description``, the open AgentSkills standard, plus an optional ``tools`` list)
followed by a markdown body of instructions. Same portable format Claude Code,
Hermes, and OpenClaw use — adopting it keeps protoPen skills shareable.

Two roots (bundle + live, later-wins by ``name``), seeded into the FTS5
``SkillsIndex`` so the retrieval/injection path lights up. Never raises — a
malformed skill is logged and skipped so one bad drop can't take down boot.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

log = logging.getLogger("protopen.skills.loader")

_MAX_DESCRIPTION = 1024  # AgentSkills caps the description (the trigger signal)


class LoadedSkill:
    __slots__ = ("name", "description", "prompt_template", "tools_used")

    def __init__(self, name: str, description: str, prompt_template: str, tools_used: list[str]):
        self.name = name
        self.description = description
        self.prompt_template = prompt_template
        self.tools_used = tools_used


def _split_frontmatter(text: str) -> tuple[dict | None, str]:
    """Return (frontmatter_dict | None, body). None when there's no `---` block."""
    if not text.lstrip().startswith("---"):
        return None, text
    stripped = text.lstrip()
    end = stripped.find("\n---", 3)
    if end == -1:
        return None, text
    fm_text = stripped[3:end]
    body = stripped[end + 4 :].lstrip("\n")
    try:
        fm = yaml.safe_load(fm_text)
    except yaml.YAMLError:
        return None, text
    return (fm if isinstance(fm, dict) else None), body


def parse_skill_md(path: Path) -> LoadedSkill | None:
    """Parse one ``SKILL.md`` into a LoadedSkill, or None if invalid (never raises)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("[skills] cannot read %s: %s", path, exc)
        return None
    fm, body = _split_frontmatter(text)
    if fm is None:
        log.warning("[skills] %s has no YAML frontmatter — skipping", path)
        return None
    name = fm.get("name")
    description = fm.get("description")
    if not isinstance(name, str) or not name.strip():
        log.warning("[skills] %s missing 'name' — skipping", path)
        return None
    if not isinstance(description, str) or not description.strip():
        log.warning("[skills] %s missing 'description' — skipping", path)
        return None
    if len(description) > _MAX_DESCRIPTION:
        log.warning("[skills] %s description > %d chars — truncating", path, _MAX_DESCRIPTION)
        description = description[:_MAX_DESCRIPTION]
    tools = fm.get("tools") or []
    tools_used = [str(t) for t in tools] if isinstance(tools, list) else []
    return LoadedSkill(name.strip(), description.strip(), (body or "").strip(), tools_used)


def discover_skills(dirs: list[str]) -> list[LoadedSkill]:
    """Discover skills across roots; later dirs win on a name clash (live > bundle)."""
    by_name: dict[str, LoadedSkill] = {}
    for d in dirs:
        root = Path(d)
        if not root.is_dir():
            continue
        for skill_md in sorted(root.glob("*/SKILL.md")):
            skill = parse_skill_md(skill_md)
            if skill is not None:
                by_name[skill.name] = skill
    return list(by_name.values())


def seed_index(index, dirs: list[str]) -> int:
    """Re-seed the index's disk skills from *dirs*. Returns the count loaded."""
    skills = discover_skills(dirs)
    index.clear_source("disk")
    for s in skills:
        index.add_skill(s.name, s.description, s.prompt_template, s.tools_used, source="disk")
    log.info("[skills] seeded %d skill(s): %s", len(skills), ", ".join(s.name for s in skills) or "(none)")
    return len(skills)
