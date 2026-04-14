"""Parser for service enumeration output — enum4linux, rpc."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

_USER_RE = re.compile(r"user:\[([^\]]+)\]", re.IGNORECASE)
_SHARE_RE = re.compile(r"^\s*([\w$]+)\s+Disk", re.MULTILINE)
_OS_RE = re.compile(r"OS=\[([^\]]+)\]")


def parse_enum4linux(raw: str, store: "TargetStore") -> list[dict]:
    """Parse enum4linux output — extract users, shares, OS info."""
    entities: list[dict] = []
    for m in _USER_RE.finditer(raw):
        entities.append({"type": "user", "username": m.group(1)})
    for m in _SHARE_RE.finditer(raw):
        entities.append({"type": "share", "name": m.group(1)})
    m = _OS_RE.search(raw)
    if m:
        entities.append({"type": "os_info", "os": m.group(1)})
    return entities


PARSER_MAP[("service_enum", "enum4linux_full")] = parse_enum4linux
PARSER_MAP[("service_enum", "rpc_users")] = parse_enum4linux
