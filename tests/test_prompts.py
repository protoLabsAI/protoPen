"""System-prompt composition — SOUL.md must actually reach the agent.

Regression guard for a latent bug: the runtime reads ``{workspace}/SOUL.md``
(default ``/sandbox/SOUL.md``), but neither the native ``start.sh`` nor the
Docker entrypoint copies SOUL there — so without a repo fallback the agent ran on
a 3-line stub identity instead of its full operating doc.
"""

from __future__ import annotations

from graph import prompts
from graph.prompts import _read_soul, build_system_prompt


def test_soul_falls_back_to_repo_config(tmp_path):
    # Empty workspace (no SOUL.md copied in) → must fall back to config/SOUL.md.
    soul = _read_soul(str(tmp_path))
    assert "I am protoPen" in soul
    assert "Autonomous Goal Pursuit" in soul  # goal mode is documented for the agent


def test_workspace_soul_takes_precedence(tmp_path):
    (tmp_path / "SOUL.md").write_text("# Custom identity\nI am a test instance.", encoding="utf-8")
    assert _read_soul(str(tmp_path)) == "# Custom identity\nI am a test instance."


def test_build_system_prompt_includes_full_soul(tmp_path):
    # Build against an empty workspace; the repo fallback must supply the real SOUL,
    # so identity + engagement modes + goal guidance are all present (not the stub).
    p = build_system_prompt(workspace=str(tmp_path), include_subagents=False)
    for marker in ("I am protoPen", "Engagement Modes", "Autonomous Goal Pursuit", "/goal <condition>"):
        assert marker in p, f"system prompt is missing {marker!r}"


def test_repo_root_points_at_repo(tmp_path):
    # Guard the path math: _REPO_ROOT/config/SOUL.md must exist.
    assert (prompts._REPO_ROOT / "config" / "SOUL.md").exists()
