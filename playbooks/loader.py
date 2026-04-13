"""Playbook loader — parse YAML playbook definitions."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from playbooks.schema import Playbook, PlaybookStep

logger = logging.getLogger(__name__)

_PLAYBOOK_DIR = Path(__file__).parent / "library"


def load_playbook(name: str, variables: dict[str, str] | None = None) -> Playbook:
    """Load a playbook from the library directory by name."""
    path = _PLAYBOOK_DIR / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Playbook '{name}' not found at {path}")
    return load_playbook_file(path, variables)


def load_playbook_file(path: Path, variables: dict[str, str] | None = None) -> Playbook:
    """Load a playbook from an arbitrary YAML file."""
    with open(path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid playbook format in {path}")

    merged_vars = {**data.get("variables", {}), **(variables or {})}

    steps = []
    for i, step_data in enumerate(data.get("steps", [])):
        params = step_data.get("params", {})
        # Substitute variables into string params
        resolved_params = _resolve_params(params, merged_vars)

        steps.append(PlaybookStep(
            name=step_data.get("name", f"step_{i}"),
            tool=step_data["tool"],
            action=step_data["action"],
            params=resolved_params,
            condition=step_data.get("condition"),
            on_fail=step_data.get("on_fail", "stop"),
            timeout=step_data.get("timeout", 300),
        ))

    return Playbook(
        name=data.get("name", path.stem),
        description=data.get("description", ""),
        steps=steps,
        variables=merged_vars,
        tags=data.get("tags", []),
    )


def list_playbooks() -> list[dict[str, str]]:
    """List all available playbooks in the library."""
    if not _PLAYBOOK_DIR.exists():
        return []
    playbooks = []
    for path in sorted(_PLAYBOOK_DIR.glob("*.yaml")):
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            playbooks.append({
                "name": path.stem,
                "description": data.get("description", ""),
                "tags": data.get("tags", []),
                "steps": len(data.get("steps", [])),
            })
        except Exception as e:
            logger.warning("Failed to parse playbook %s: %s", path, e)
    return playbooks


def _resolve_params(
    params: dict[str, Any],
    variables: dict[str, str],
) -> dict[str, Any]:
    """Substitute ${var} references in string param values."""
    resolved = {}
    for key, value in params.items():
        if isinstance(value, str):
            for var_name, var_value in variables.items():
                value = value.replace(f"${{{var_name}}}", str(var_value))
            resolved[key] = value
        else:
            resolved[key] = value
    return resolved
