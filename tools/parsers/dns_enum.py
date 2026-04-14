"""Parser for DNS enumeration output — dig, zone transfer."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

_DIG_ANSWER_RE = re.compile(
    r"^(\S+)\s+\d+\s+IN\s+(A|AAAA)\s+(\S+)",
    re.MULTILINE,
)


def parse_dig(raw: str, store: "TargetStore") -> list[dict]:
    """Parse dig +answer output and upsert hosts for A/AAAA records."""
    entities: list[dict] = []
    for m in _DIG_ANSWER_RE.finditer(raw):
        hostname = m.group(1).rstrip(".")
        ip = m.group(3)
        store.upsert_host(ip=ip, hostname=hostname)
        entities.append({"type": "host", "ip": ip, "hostname": hostname})
    return entities


def parse_zone_transfer(raw: str, store: "TargetStore") -> list[dict]:
    """Parse AXFR output — same A/AAAA pattern as dig."""
    return parse_dig(raw, store)


PARSER_MAP[("dns_enum", "dig_query")] = parse_dig
PARSER_MAP[("dns_enum", "zone_transfer")] = parse_zone_transfer
PARSER_MAP[("dns_enum", "reverse_lookup")] = parse_dig
