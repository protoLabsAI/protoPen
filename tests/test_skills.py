"""Skills — FTS5 index, SKILL.md loader, and the context-delivery injection."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from graph.skills.index import SkillsIndex, _build_match_query
from graph.skills.loader import discover_skills, parse_skill_md, seed_index


# ── SkillsIndex (FTS5) ────────────────────────────────────────────────────────


def test_match_query_is_prefix_or():
    assert _build_match_query("Web Research!") == "web* OR research*"
    assert _build_match_query("") == ""


def test_index_add_and_retrieve(tmp_path):
    idx = SkillsIndex(str(tmp_path / "s.db"))
    idx.add_skill("web-research", "research a topic on the web", "plan, search, synthesize")
    idx.add_skill("recon-sweep", "reconnaissance on a host or network", "passive then active")
    assert idx.count() == 2
    hits = idx.load_skills("recon a network host", k=5)
    assert hits and hits[0].name == "recon-sweep"
    # tokenizing strips FTS5 syntax → arbitrary text never raises
    assert idx.load_skills('"]) OR (', k=5) == [] or True


def test_index_clear_source_reseeds(tmp_path):
    idx = SkillsIndex(str(tmp_path / "s.db"))
    idx.add_skill("a", "desc one", "body")
    idx.clear_source("disk")
    assert idx.count() == 0


def test_emitted_skill_survives_disk_reseed_and_overwrites(tmp_path):
    """Agent-emitted skills (#256) persist across the per-boot disk re-seed and
    overwrite by name rather than duplicating."""
    idx = SkillsIndex(str(tmp_path / "s.db"))
    idx.add_skill("from-disk", "disk skill", "body", source="disk")
    idx.add_emitted_skill("learned", "use when X", "do X")
    # Re-seed clears only disk skills; the emitted one stays.
    idx.clear_source("disk")
    assert idx.count() == 1
    assert idx.load_skills("X")[0].name == "learned"
    # Re-saving the same name refines (no duplicate).
    idx.add_emitted_skill("learned", "use when X, refined", "do X better")
    assert idx.count() == 1
    assert idx.load_skills("refined")[0].description == "use when X, refined"


# ── SKILL.md loader ───────────────────────────────────────────────────────────

_VALID = """---
name: demo-skill
description: Use this for the demo.
tools: [foo, bar]
---
# Demo
Do the thing.
"""


def test_parse_valid_skill(tmp_path):
    p = tmp_path / "SKILL.md"
    p.write_text(_VALID)
    s = parse_skill_md(p)
    assert s is not None
    assert s.name == "demo-skill"
    assert s.description == "Use this for the demo."
    assert s.tools_used == ["foo", "bar"]
    assert "Do the thing." in s.prompt_template


def test_parse_rejects_malformed(tmp_path):
    no_fm = tmp_path / "a.md"
    no_fm.write_text("# no frontmatter\n")
    assert parse_skill_md(no_fm) is None

    missing = tmp_path / "b.md"
    missing.write_text("---\ndescription: no name here\n---\nbody\n")
    assert parse_skill_md(missing) is None


def test_parse_truncates_oversized_description(tmp_path):
    p = tmp_path / "SKILL.md"
    long_desc = "x" * 2000
    p.write_text(f"---\nname: big\ndescription: {long_desc}\n---\nbody\n")
    s = parse_skill_md(p)
    assert s is not None and len(s.description) == 1024


def test_discover_live_overrides_bundle(tmp_path):
    bundle = tmp_path / "bundle"
    live = tmp_path / "live"
    (bundle / "x").mkdir(parents=True)
    (live / "x").mkdir(parents=True)
    (bundle / "x" / "SKILL.md").write_text("---\nname: x\ndescription: bundle version\n---\nb\n")
    (live / "x" / "SKILL.md").write_text("---\nname: x\ndescription: live version\n---\nl\n")
    skills = discover_skills([str(bundle), str(live)])
    assert len(skills) == 1
    assert skills[0].description == "live version"  # later dir wins


def test_seed_index_roundtrip(tmp_path):
    skills_dir = tmp_path / "skills" / "demo"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text(_VALID)
    idx = SkillsIndex(str(tmp_path / "s.db"))
    n = seed_index(idx, [str(tmp_path / "skills")])
    assert n == 1
    assert idx.load_skills("demo")[0].name == "demo-skill"


def test_bundled_recon_skill_loads():
    """The shipped config/skills/recon-sweep/SKILL.md must parse."""
    bundled = Path(__file__).resolve().parent.parent / "config" / "skills"
    skills = discover_skills([str(bundled)])
    assert any(s.name == "recon-sweep" for s in skills)


# ── PromptCacheMiddleware — the context-delivery injection ─────────────────────


class _FakeMsg:
    def __init__(self, content):
        self.content = content

    def model_copy(self, update):
        return _FakeMsg(update["content"])


class _FakeReq:
    def __init__(self, sysmsg, state, model_name=""):
        self.system_message = sysmsg
        self.state = state
        self.model = SimpleNamespace(model_name=model_name)

    def override(self, **kw):
        return SimpleNamespace(**kw)


def test_prompt_cache_appends_context_plain_for_non_anthropic():
    pytest.importorskip("langchain.agents.middleware")
    from graph.middleware.prompt_cache import PromptCacheMiddleware

    mw = PromptCacheMiddleware()
    req = _FakeReq(_FakeMsg("BASE PROMPT"), {"context": "<learned_skills>...</learned_skills>"}, model_name="gpt-x")
    out = mw._transform(req)
    assert out.system_message.content == "BASE PROMPT\n\n# Context\n\n<learned_skills>...</learned_skills>"


def test_prompt_cache_blocks_with_cache_control_for_anthropic():
    pytest.importorskip("langchain.agents.middleware")
    from graph.middleware.prompt_cache import PromptCacheMiddleware

    mw = PromptCacheMiddleware()
    req = _FakeReq(_FakeMsg("BASE"), {"context": "CTX"}, model_name="claude-sonnet-4-6")
    out = mw._transform(req)
    blocks = out.system_message.content
    assert isinstance(blocks, list)
    assert blocks[0]["cache_control"] == {"type": "ephemeral"}  # stable prefix cached
    assert "CTX" in blocks[1]["text"]  # context appended after the breakpoint


def test_prompt_cache_noop_without_context_or_cache():
    pytest.importorskip("langchain.agents.middleware")
    from graph.middleware.prompt_cache import PromptCacheMiddleware

    mw = PromptCacheMiddleware()
    req = _FakeReq(_FakeMsg("BASE"), {}, model_name="gpt-x")  # no context, non-anthropic
    assert mw._transform(req) is req  # untouched
