"""Parser for OSINT recon output — theHarvester."""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"\b[\w.-]+\.[\w]{2,}\b")


def parse_theharvester(raw: str, store: "TargetStore") -> list[dict]:
    """Parse theHarvester output for IPs and hostnames."""
    entities: list[dict] = []
    in_hosts = False
    in_ips = False
    for line in raw.splitlines():
        stripped = line.strip()
        if "Hosts found" in stripped:
            in_hosts, in_ips = True, False
            continue
        if "IPs found" in stripped:
            in_ips, in_hosts = True, False
            continue
        if stripped.startswith("[*]") or stripped.startswith("---"):
            in_hosts = in_ips = False
            continue
        if in_hosts and stripped:
            parts = stripped.split(":")
            if len(parts) >= 2:
                ip, hostname = parts[0].strip(), parts[1].strip()
                store.upsert_host(ip=ip, hostname=hostname)
                entities.append({"type": "host", "ip": ip, "hostname": hostname})
            elif _HOST_RE.match(stripped):
                store.upsert_host(hostname=stripped)
                entities.append({"type": "host", "hostname": stripped})
        elif in_ips and stripped:
            for ip in _IP_RE.findall(stripped):
                store.upsert_host(ip=ip)
                entities.append({"type": "host", "ip": ip})
    return entities


PARSER_MAP[("osint_recon", "theharvester")] = parse_theharvester
