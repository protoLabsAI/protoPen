"""Operator console playbook contracts — list + manual run (Phase 1)."""

from __future__ import annotations

import asyncio

import pytest

from operator_api.playbooks import list_playbooks_for_console, run_manual_playbook


def test_list_playbooks_has_library_with_variables_and_steps():
    out = list_playbooks_for_console()
    assert out["count"] >= 20  # 23 bundled
    assert out["count"] == len(out["playbooks"])
    by_name = {p["name"]: p for p in out["playbooks"]}
    assert "external_recon" in by_name
    pb = by_name["external_recon"]
    assert pb["description"]
    assert isinstance(pb["tags"], list) and pb["tags"]
    assert isinstance(pb["variables"], dict)  # declared vars (defaults) for the form
    assert pb["steps"] and {"name", "tool", "action"} <= set(pb["steps"][0])


def test_run_unknown_playbook_raises_value_error():
    # Bad name fails at load, before the heavy tool registry import.
    with pytest.raises(ValueError, match="not found"):
        asyncio.run(run_manual_playbook("does-not-exist-xyz"))


def test_run_requires_a_name():
    with pytest.raises(ValueError, match="required"):
        asyncio.run(run_manual_playbook("   "))
