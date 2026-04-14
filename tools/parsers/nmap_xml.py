"""Parser for nmap -oX - XML output → hosts + ports into TargetStore."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

logger = logging.getLogger(__name__)


def parse(raw: str, store: TargetStore) -> list[dict]:
    """Parse nmap XML, upsert hosts and ports, return entity list."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        logger.debug("nmap parser: not valid XML, skipping")
        return []

    entities: list[dict] = []

    for host_el in root.findall("host"):
        ip = ""
        mac = ""
        vendor = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")

        hostname = ""
        hn_el = host_el.find("hostnames/hostname")
        if hn_el is not None:
            hostname = hn_el.get("name", "")

        os_match = ""
        os_el = host_el.find("os/osmatch")
        if os_el is not None:
            os_match = os_el.get("name", "")

        if not ip and not mac:
            continue

        host_id = store.upsert_host(
            ip=ip,
            mac=mac,
            hostname=hostname,
            os=os_match,
            vendor=vendor,
        )
        entities.append(
            {
                "type": "host",
                "id": host_id,
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "os": os_match,
                "vendor": vendor,
            }
        )

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            protocol = port_el.get("protocol", "tcp")
            portid = int(port_el.get("portid", 0))
            state_el = port_el.find("state")
            state = state_el.get("state", "open") if state_el is not None else "open"
            svc_el = port_el.find("service")
            service = ""
            banner = ""
            if svc_el is not None:
                service = svc_el.get("name", "")
                product = svc_el.get("product", "")
                version = svc_el.get("version", "")
                if product:
                    banner = f"{product} {version}".strip()

            port_row_id = store.upsert_port(
                host_id=host_id,
                port=portid,
                protocol=protocol,
                state=state,
                service=service,
                banner=banner,
            )
            entities.append(
                {
                    "type": "port",
                    "id": port_row_id,
                    "host_id": host_id,
                    "port": portid,
                    "protocol": protocol,
                    "service": service,
                    "banner": banner,
                }
            )

    return entities


PARSER_MAP[("blackarch", "nmap_scan")] = parse
PARSER_MAP[("blackarch", "nmap_vuln_scan")] = parse
PARSER_MAP[("blackarch", "nmap_os_detect")] = parse
PARSER_MAP[("blackarch", "nmap_udp_scan")] = parse
