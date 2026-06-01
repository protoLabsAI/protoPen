"""Operator console playbook contracts — list + manual run + the Phase 2 gate."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace as NS

import pytest

from operator_api.playbooks import (
    PlaybookGateError,
    _enforce_gate,
    _playbook_risk,
    _scope_config_from_string,
    list_playbooks_for_console,
    run_manual_playbook,
)


def _step(name, tool, action, params=None):
    return NS(name=name, tool=tool, action=action, params=params or {})


def test_list_playbooks_has_library_with_mode_variables_and_steps():
    out = list_playbooks_for_console()
    assert out["count"] >= 20  # 23 bundled
    assert out["count"] == len(out["playbooks"])
    by_name = {p["name"]: p for p in out["playbooks"]}
    pb = by_name["external_recon"]
    assert pb["description"] and isinstance(pb["tags"], list) and pb["tags"]
    assert isinstance(pb["variables"], dict)  # declared vars (defaults) for the form
    assert pb["steps"] and {"name", "tool", "action"} <= set(pb["steps"][0])
    assert pb["mode"] in {"passive", "active", "redteam"}
    # The library is not uniformly passive — offensive recipes are classified up.
    modes = {p["mode"] for p in out["playbooks"]}
    assert modes & {"active", "redteam"}
    # mode and requires_engagement agree.
    for p in out["playbooks"]:
        assert p["requires_engagement"] == (p["mode"] != "passive")


# ── Phase 2 gate ──────────────────────────────────────────────────────────────


def test_risk_uses_action_then_tool_then_tag_floor():
    # action-keyed risk (cve_nmap=2 in config) → redteam
    assert _playbook_risk([_step("s", "cve_match", "cve_nmap")]) == 2
    # unknown action, but an offensive tag floors it to active
    assert _playbook_risk([_step("s", "x", "unknown_action")], ["exploit"]) == 1
    # all-unknown, no offensive tags → passive
    assert _playbook_risk([_step("s", "engagement", "transition_phase")], ["recon"]) == 0


def test_gate_passes_passive_without_engagement():
    pb = NS(steps=[_step("s", "engagement", "transition_phase")], tags=["recon"])
    assert _enforce_gate(pb, None) == "passive"


def test_gate_blocks_offensive_without_engagement():
    pb = NS(steps=[_step("s", "cve_match", "cve_nmap", {"target": "10.0.0.5"})], tags=["redteam"])
    with pytest.raises(PlaybookGateError) as ei:
        _enforce_gate(pb, None)
    assert ei.value.status_code == 409


def test_gate_blocks_when_mode_insufficient():
    pb = NS(steps=[_step("s", "cve_match", "cve_nmap")], tags=[])  # risk 2 → needs redteam
    mgr = NS(active_engagement={"scope": ""}, mode=NS(value=1, name="ACTIVE"))
    with pytest.raises(PlaybookGateError):
        _enforce_gate(pb, mgr)


def test_gate_blocks_out_of_scope_target():
    # nmap_scan's target arg is extracted by ScopeValidator; 8.8.8.8 ∉ 10.0.0.0/24.
    pb = NS(steps=[_step("s", "blackarch", "nmap_scan", {"target": "8.8.8.8"})], tags=["redteam"])
    mgr = NS(active_engagement={"scope": "10.0.0.0/24"}, mode=NS(value=2, name="REDTEAM"))
    with pytest.raises(PlaybookGateError, match="scope"):
        _enforce_gate(pb, mgr)


def test_gate_allows_in_scope_target():
    pb = NS(steps=[_step("s", "blackarch", "nmap_scan", {"target": "10.0.0.5"})], tags=["redteam"])
    mgr = NS(active_engagement={"scope": "10.0.0.0/24"}, mode=NS(value=2, name="REDTEAM"))
    assert _enforce_gate(pb, mgr) == "redteam"


def test_scope_config_inference():
    assert _scope_config_from_string("10.0.0.0/24")["type"] == "cidr"
    dom = _scope_config_from_string("example.com")
    assert dom["type"] == "domain" and "*.example.com" in dom["targets"]
    assert _scope_config_from_string("")["type"] == "any"


def test_run_unknown_playbook_raises_value_error():
    # Bad name fails at load, before the heavy tool registry import.
    with pytest.raises(ValueError, match="not found"):
        asyncio.run(run_manual_playbook("does-not-exist-xyz"))


def test_run_requires_a_name():
    with pytest.raises(ValueError, match="required"):
        asyncio.run(run_manual_playbook("   "))
