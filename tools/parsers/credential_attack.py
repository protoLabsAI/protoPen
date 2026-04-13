"""Parser for hydra credential attack output."""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

_HYDRA_SUCCESS_RE = re.compile(
    r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)"
)


def parse_hydra(raw: str, store: "TargetStore") -> list[dict]:
    """Parse hydra output for successful logins."""
    entities: list[dict] = []
    for m in _HYDRA_SUCCESS_RE.finditer(raw):
        entities.append({
            "type": "credential",
            "port": int(m.group(1)),
            "service": m.group(2),
            "host": m.group(3),
            "username": m.group(4),
            "password": m.group(5),
        })
    return entities


PARSER_MAP[("credential_attack", "hydra_brute")] = parse_hydra
PARSER_MAP[("credential_attack", "hydra_spray")] = parse_hydra
PARSER_MAP[("credential_attack", "hydra_combo")] = parse_hydra
