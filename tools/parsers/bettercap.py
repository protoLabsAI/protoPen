"""Parser for bettercap net.show ASCII table → hosts into TargetStore."""

from __future__ import annotations

import re
import logging
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

logger = logging.getLogger(__name__)

# Matches table rows with │-delimited columns:
#   │ IP │ MAC │ Hostname │ Vendor │ Sent │ Recvd │
_ROW_RE = re.compile(
    r"│\s*(\d{1,3}(?:\.\d{1,3}){3})\s*│\s*"
    r"([0-9A-Fa-f:]{17})\s*│\s*"
    r"(.*?)\s*│\s*"
    r"(.*?)\s*│\s*"
    r".*?│\s*.*?│"
)


def parse(raw: str, store: TargetStore) -> list[dict]:
    """Parse bettercap net.show table, upsert hosts, return entity list."""
    entities: list[dict] = []
    for m in _ROW_RE.finditer(raw):
        ip = m.group(1)
        mac = m.group(2).upper()
        hostname = m.group(3).strip()
        vendor = m.group(4).strip()

        host_id = store.upsert_host(
            ip=ip,
            mac=mac,
            hostname=hostname,
            vendor=vendor,
        )
        entities.append(
            {
                "type": "host",
                "id": host_id,
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
            }
        )
    return entities


PARSER_MAP[("blackarch", "bettercap_recon")] = parse
