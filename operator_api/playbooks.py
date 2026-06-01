"""Playbook browse + manual run for the operator console (Phase 1).

protoPen ships 23 declarative playbooks (``playbooks/library/*.yaml`` — ordered
tool-chains, no LLM). The agent reaches them via the ``playbook`` tool; this
exposes the same library to the operator: list them with their variables + step
preview, and fire one manually. The run reuses the *exact* dispatch + runner the
agent's tool uses (``dispatch_pentest_tool`` + ``run_playbook``), so step
semantics (conditions, chaining, on_fail, findings-aware skips) stay identical.

Operator-key-gated like the rest of the console. Mode/scope enforcement (gating
active/redteam fires on an active engagement) lands in Phase 2 — this module is
the browse + run plumbing.
"""

from __future__ import annotations

from typing import Any


def list_playbooks_for_console() -> dict[str, Any]:
    """List the playbook library with enough detail to render + collect inputs.

    Each entry: name, description, tags, declared variables (defaults), and a
    step preview (name · tool.action). Tolerant of a malformed recipe — it's
    skipped rather than failing the whole list.
    """
    from playbooks.loader import list_playbooks, load_playbook

    playbooks: list[dict[str, Any]] = []
    for summary in list_playbooks():
        name = summary.get("name", "")
        if not name:
            continue
        try:
            pb = load_playbook(name)
        except Exception:
            continue
        playbooks.append(
            {
                "name": name,
                "description": pb.description or summary.get("description", ""),
                "tags": list(pb.tags or summary.get("tags", [])),
                "variables": dict(pb.variables or {}),
                "steps": [{"name": s.name, "tool": s.tool, "action": s.action} for s in pb.steps],
            }
        )
    return {"count": len(playbooks), "playbooks": playbooks}


async def run_manual_playbook(name: str, variables: dict[str, str] | None = None) -> dict[str, Any]:
    """Load + run a playbook by name, returning its ``to_dict()`` result.

    Raises ValueError for an unknown playbook (→ 404/400 at the route). Reuses the
    agent's tool dispatch + runner so the manual run behaves identically to the
    agent firing the same playbook. The active engagement (if any) is passed
    through so findings-based step conditions evaluate.
    """
    cleaned = (name or "").strip()
    if not cleaned:
        raise ValueError("playbook name is required")

    # Resolve the recipe first — a bad name fails here without pulling the (heavy)
    # tool registry.
    from playbooks.loader import load_playbook

    try:
        playbook = load_playbook(cleaned, variables or {})
    except FileNotFoundError as exc:
        raise ValueError(f"playbook not found: {cleaned}") from exc

    from playbooks.runner import run_playbook
    from tools.lg_tools import dispatch_pentest_tool, get_engagement_manager

    try:
        engagement_mgr = get_engagement_manager()
    except Exception:
        engagement_mgr = None

    result = await run_playbook(playbook, dispatch_pentest_tool, engagement_mgr=engagement_mgr)
    return result.to_dict()
