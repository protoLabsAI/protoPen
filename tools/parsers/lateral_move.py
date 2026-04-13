"""Parser for lateral movement output."""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

_SHELL_RE = re.compile(r"(C:\\|/root/|/home/\w+)")


def parse_shell(raw: str, store: "TargetStore") -> list[dict]:
    """Parse shell output — detect successful shell access."""
    entities: list[dict] = []
    if _SHELL_RE.search(raw):
        entities.append({"type": "shell_access", "evidence": raw[:200]})
    return entities


PARSER_MAP[("lateral_move", "psexec")] = parse_shell
PARSER_MAP[("lateral_move", "wmiexec")] = parse_shell
PARSER_MAP[("lateral_move", "evil_winrm")] = parse_shell
PARSER_MAP[("lateral_move", "pth_winrm")] = parse_shell
