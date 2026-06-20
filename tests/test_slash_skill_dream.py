"""On-demand /skill + /dream slash dispatch + dream cadence (protopen-1hw.13 / 1hw.14)."""

from __future__ import annotations

import asyncio
import importlib

from graph.config import LangGraphConfig

# server.chat the submodule is shadowed by the `chat` function imported into the
# server package namespace, so attribute access (`server.chat`) yields the function.
# Grab the real module object for monkeypatching.
chat_mod = importlib.import_module("server.chat")
from graph.skills import SkillsIndex
from runtime.state import STATE


def _seed_skills(tmp_path):
    idx = SkillsIndex(db_path=str(tmp_path / "s.db"))
    idx.add_skill("nuke", "destructive teardown", "step 1: confirm scope\nstep 2: run", user_only=True)
    STATE.skills_index = idx
    return idx


# ── /skill resolution ────────────────────────────────────────────────────────


def test_skill_run_input_resolves_body_and_extra(tmp_path):
    _seed_skills(tmp_path)
    try:
        out = chat_mod._skill_run_input("nuke target=10.0.0.5")
        assert "step 1: confirm scope" in out  # body
        assert "target=10.0.0.5" in out  # extra context threaded
        assert chat_mod._skill_run_input("missing") is None
        assert chat_mod._skill_run_input("") is None
    finally:
        STATE.skills_index = None


def test_chat_slash_skill_runs_body(tmp_path, monkeypatch):
    _seed_skills(tmp_path)
    seen = {}

    async def fake_lg(message, session_id):
        seen["msg"] = message
        return [{"role": "assistant", "content": "ran"}]

    monkeypatch.setattr(chat_mod, "_chat_langgraph", fake_lg)
    monkeypatch.setattr(STATE, "goal_controller", None, raising=False)
    try:
        res = asyncio.run(chat_mod.chat("/skill nuke", "sess"))
        assert res == [{"role": "assistant", "content": "ran"}]
        assert "step 1: confirm scope" in seen["msg"]  # skill body became the turn input
        # unknown skill → message, no agent run
        seen.clear()
        res2 = asyncio.run(chat_mod.chat("/skill ghost", "sess"))
        assert "No such skill" in res2[0]["content"] and "msg" not in seen
    finally:
        STATE.skills_index = None


# ── /dream ───────────────────────────────────────────────────────────────────


def test_chat_slash_dream_runs_subagent(monkeypatch):
    async def fake_dream(session_id):
        return "DREAM-REPORT: pruned 2 dups"

    monkeypatch.setattr(chat_mod, "_run_dream", fake_dream)
    monkeypatch.setattr(STATE, "goal_controller", None, raising=False)
    res = asyncio.run(chat_mod.chat("/dream", "sess"))
    assert res[0]["content"] == "DREAM-REPORT: pruned 2 dups"


def test_run_dream_delegates_to_dream_subagent(monkeypatch):
    captured = {}

    async def fake_run_manual(config, ks, sched, *, description, prompt, subagent_type, **kw):
        captured["type"] = subagent_type
        return "ok report"

    import graph.agent as agent_mod

    monkeypatch.setattr(agent_mod, "run_manual_subagent", fake_run_manual)
    monkeypatch.setattr(STATE, "graph_config", LangGraphConfig(api_key="x"), raising=False)
    out = asyncio.run(chat_mod._run_dream("sess"))
    assert out == "ok report" and captured["type"] == "dream"


# ── cadence config ───────────────────────────────────────────────────────────


def test_dream_cadence_cron_config_default():
    assert LangGraphConfig(api_key="x").dream_cadence_cron == ""


def test_slash_commands_registered():
    from server import _CHAT_COMMANDS

    names = {c["name"] for c in _CHAT_COMMANDS}
    assert {"skill", "dream"} <= names
