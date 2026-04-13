"""Parser for subdomain discovery output — subfinder and amass."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_subfinder(raw: str, store: "TargetStore") -> list[dict]:
    """Parse subfinder JSON-lines output and upsert hosts."""
    entities: list[dict] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            host = data.get("host", "")
            ip = data.get("ip", "")
            if host:
                store.upsert_host(ip=ip, hostname=host)
                entities.append({"type": "host", "hostname": host, "ip": ip})
        except json.JSONDecodeError:
            # Plain text line — treat as subdomain
            if "." in line and " " not in line:
                store.upsert_host(hostname=line)
                entities.append({"type": "host", "hostname": line})
    return entities


def parse_amass(raw: str, store: "TargetStore") -> list[dict]:
    """Parse amass JSON output and upsert hosts."""
    entities: list[dict] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            name = data.get("name", "")
            addresses = data.get("addresses", [])
            if name:
                ip = addresses[0].get("ip", "") if addresses else ""
                store.upsert_host(ip=ip, hostname=name)
                entities.append({"type": "host", "hostname": name, "ip": ip})
        except json.JSONDecodeError:
            pass
    return entities


PARSER_MAP[("subdomain_discovery", "subfinder")] = parse_subfinder
PARSER_MAP[("subdomain_discovery", "amass_passive")] = parse_amass
