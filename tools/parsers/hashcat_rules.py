"""Parser for hashcat / john output."""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

_HASHCAT_LINE_RE = re.compile(r"^(\S+):(\S+)$", re.MULTILINE)
_HASHID_RE = re.compile(r"\[.\]\s+(.*)")


def parse_hashid(raw: str, store: "TargetStore") -> list[dict]:
    """Parse hashid output."""
    entities: list[dict] = []
    for m in _HASHID_RE.finditer(raw):
        entities.append({"type": "hash_type", "name": m.group(1).strip()})
    return entities


def parse_hashcat(raw: str, store: "TargetStore") -> list[dict]:
    """Parse hashcat cracked output (hash:plaintext)."""
    entities: list[dict] = []
    for m in _HASHCAT_LINE_RE.finditer(raw):
        entities.append({
            "type": "cracked_hash",
            "hash": m.group(1),
            "plaintext": m.group(2),
        })
    return entities


PARSER_MAP[("hashcat_rules", "hash_identify")] = parse_hashid
PARSER_MAP[("hashcat_rules", "hashcat_dict")] = parse_hashcat
PARSER_MAP[("hashcat_rules", "hashcat_rules")] = parse_hashcat
PARSER_MAP[("hashcat_rules", "john_crack")] = parse_hashcat
PARSER_MAP[("hashcat_rules", "john_show")] = parse_hashcat
