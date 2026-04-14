"""LangGraph tool wrapper for the playbook system."""

from __future__ import annotations

import json
import logging
from typing import Any

from playbooks.loader import list_playbooks, load_playbook
from playbooks.runner import run_playbook
from playbooks.schema import Playbook

logger = logging.getLogger(__name__)

# Singleton: the last-run playbook for status queries
_active_playbook: Playbook | None = None


async def execute_playbook_action(
    action: str,
    name: str = "",
    variables: str = "",
    dispatch_fn=None,
) -> str:
    """Execute playbook system actions.

    Actions:
        list: List available playbooks
        run: Run a playbook by name (requires dispatch_fn)
        status: Get status of the active playbook
    """
    global _active_playbook

    if action == "list":
        playbooks = list_playbooks()
        if not playbooks:
            return "No playbooks found in library."
        lines = ["Available playbooks:"]
        for pb in playbooks:
            tags = ", ".join(pb.get("tags", []))
            lines.append(f"  • {pb['name']} ({pb['steps']} steps) [{tags}] — {pb['description']}")
        return "\n".join(lines)

    elif action == "run":
        if not name:
            return "Error: 'name' parameter required for run action."
        if not dispatch_fn:
            return "Error: No tool dispatcher available."

        # Parse variables from JSON string
        vars_dict: dict[str, str] = {}
        if variables:
            try:
                vars_dict = json.loads(variables)
            except json.JSONDecodeError:
                return f"Error: Invalid JSON in variables: {variables}"

        try:
            playbook = load_playbook(name, vars_dict)
        except FileNotFoundError as e:
            return str(e)

        _active_playbook = playbook
        result = await run_playbook(playbook, dispatch_fn)
        _active_playbook = result

        return json.dumps(result.to_dict(), indent=2)

    elif action == "status":
        if _active_playbook is None:
            return "No active playbook."
        return json.dumps(_active_playbook.to_dict(), indent=2)

    else:
        return f"Unknown playbook action: {action}. Available: list, run, status"
