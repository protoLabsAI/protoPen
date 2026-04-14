"""Parser for privilege escalation output."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

_SUID_RE = re.compile(r"-[rwxs-]+\s+\d+\s+\S+\s+\S+\s+\d+\s+\S+\s+\d+\s+\S+\s+(\S+)")
_SUDO_RE = re.compile(r"\((\S+)\)\s+(NOPASSWD:\s+)?(.+)")


def parse_suid(raw: str, store: "TargetStore") -> list[dict]:
    """Parse SUID binary find output."""
    entities: list[dict] = []
    for m in _SUID_RE.finditer(raw):
        entities.append({"type": "suid_binary", "path": m.group(1)})
    return entities


def parse_sudo(raw: str, store: "TargetStore") -> list[dict]:
    """Parse sudo -l output."""
    entities: list[dict] = []
    for m in _SUDO_RE.finditer(raw):
        entities.append(
            {
                "type": "sudo_rule",
                "runas": m.group(1),
                "nopasswd": bool(m.group(2)),
                "command": m.group(3).strip(),
            }
        )
    return entities


PARSER_MAP[("priv_esc", "suid_find")] = parse_suid
PARSER_MAP[("priv_esc", "sudo_check")] = parse_sudo
