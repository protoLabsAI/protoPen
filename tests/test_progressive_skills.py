"""Progressive skill disclosure (protopen-1hw.13): catalog injection + load_skill."""

from __future__ import annotations

import asyncio

from langchain_core.messages import HumanMessage

from graph.agent import _build_load_skill_tool
from graph.middleware.knowledge import KnowledgeMiddleware
from graph.skills import SkillsIndex


def _idx(tmp_path):
    idx = SkillsIndex(db_path=str(tmp_path / "s.db"))
    idx.add_skill("pentest", "web/network assessment methodology", "STEP 1: scope\nSTEP 2: scan", ["dns_enum"])
    idx.add_skill("recon-sweep", "subnet enumeration", "RECON BODY", user_only=True)
    return idx


def _ctx(mw):
    out = mw.before_model({"messages": [HumanMessage(content="assess the target host")]}, None)
    return (out or {}).get("context", "")


def test_progressive_injects_catalog_not_bodies(tmp_path):
    mw = KnowledgeMiddleware(knowledge_store=None, skills_index=_idx(tmp_path), progressive_skills=True)
    ctx = _ctx(mw)
    assert "<available_skills>" in ctx
    assert "pentest: web/network assessment methodology" in ctx  # name + description
    assert "STEP 1: scope" not in ctx  # body NOT injected
    assert "load_skill(" in ctx  # tells the agent how to pull a body
    assert "recon-sweep" not in ctx  # user_only hidden from the catalog


def test_legacy_mode_still_injects_bodies(tmp_path):
    mw = KnowledgeMiddleware(knowledge_store=None, skills_index=_idx(tmp_path), progressive_skills=False)
    out = mw.before_model({"messages": [HumanMessage(content="web network assessment")]}, None)
    ctx = (out or {}).get("context", "")
    assert "<learned_skills>" in ctx
    assert "STEP 1: scope" in ctx  # full body injected (legacy)


def test_load_skill_tool_returns_body_including_user_only(tmp_path):
    lt = _build_load_skill_tool(_idx(tmp_path))
    out = asyncio.run(lt.coroutine(name="recon-sweep"))  # user_only — catalog-hidden but loadable
    assert "RECON BODY" in out and "recon-sweep" in out
    assert asyncio.run(lt.coroutine(name="missing")).startswith("No skill")


def test_catalog_falls_back_to_topk_when_oversized(tmp_path):
    idx = SkillsIndex(db_path=str(tmp_path / "big.db"))
    # Many skills with long descriptions → catalog exceeds the token budget.
    for i in range(200):
        idx.add_skill(f"skill_{i}", "recon " + ("enumeration discovery " * 20), f"body {i}")
    mw = KnowledgeMiddleware(knowledge_store=None, skills_index=idx, progressive_skills=True)
    out = mw.before_model({"messages": [HumanMessage(content="recon enumeration")]}, None)
    ctx = (out or {}).get("context", "")
    assert "<available_skills>" in ctx
    # Bounded: not all 200 are listed.
    assert ctx.count("\n  - ") < 200
