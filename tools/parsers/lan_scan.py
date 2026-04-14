"""Parser for lan_scan tool output — ARP sweep, NetBIOS, SNMP, mDNS, SMB."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

# ── ARP sweep (arp-scan) ────────────────────────────────────────────────────

# arp-scan line:  192.168.1.1\t00:11:22:33:44:55\tCisco Systems, Inc
_ARP_LINE_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:]{17})\s*(.*)?$"
)


def parse_arp_sweep(raw: str, store: "TargetStore") -> list[dict]:
    """Parse arp-scan output — upsert discovered hosts, return lan_host dicts."""
    entities: list[dict] = []
    for line in raw.splitlines():
        m = _ARP_LINE_RE.match(line.strip())
        if not m:
            continue
        ip, mac, vendor = m.group(1), m.group(2), m.group(3).strip()
        store.upsert_host(ip=ip, mac=mac, vendor=vendor)
        entities.append(
            {
                "type": "lan_host",
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
            }
        )
    return entities


# ── netdiscover ─────────────────────────────────────────────────────────────

# netdiscover -P line examples:
#   192.168.1.1  00:11:22:33:44:55    1    60  Cisco Systems, Inc
# or tab-separated variants — try both
_NETDISC_TAB_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})[\s\t]+([0-9a-fA-F:]{17})[\s\t]+\d+[\s\t]+\d+[\s\t]*(.*)?$"
)


def parse_netdiscover(raw: str, store: "TargetStore") -> list[dict]:
    """Parse netdiscover -P output — upsert hosts, return lan_host dicts."""
    entities: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _NETDISC_TAB_RE.match(line)
        if not m:
            # Fallback: try same regex as arp_sweep (tab-sep IP/MAC/vendor)
            m = _ARP_LINE_RE.match(line)
        if not m:
            continue
        ip, mac = m.group(1), m.group(2)
        vendor = m.group(3).strip() if m.lastindex and m.lastindex >= 3 else ""
        store.upsert_host(ip=ip, mac=mac, vendor=vendor)
        entities.append(
            {
                "type": "lan_host",
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
            }
        )
    return entities


# ── nbtscan ─────────────────────────────────────────────────────────────────

# nbtscan output line:
#   192.168.1.10    WORKGROUP\DESKTOP-ABC    SHARING
# or:
#   192.168.1.10    DESKTOP-ABC<00>    UNIQUE    WORKGROUP
_NBTSCAN_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)"
)
_WORKGROUP_RE = re.compile(r"^([^\\]+)\\(.+)$")


def parse_nbtscan(raw: str, store: "TargetStore") -> list[dict]:
    """Parse nbtscan output — extract Windows hosts, workgroup names."""
    entities: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("IP") or line.startswith("-"):
            continue
        m = _NBTSCAN_RE.match(line)
        if not m:
            continue
        ip = m.group(1)
        name_field = m.group(2)

        workgroup = ""
        hostname = name_field
        wg_m = _WORKGROUP_RE.match(name_field)
        if wg_m:
            workgroup = wg_m.group(1)
            hostname = wg_m.group(2)
        else:
            # Try to extract workgroup from remainder of line
            rest = line[m.end():].strip()
            parts = rest.split()
            if parts:
                workgroup = parts[-1]

        store.upsert_host(ip=ip, hostname=hostname)
        entities.append(
            {
                "type": "windows_host",
                "ip": ip,
                "hostname": hostname,
                "workgroup": workgroup,
            }
        )
    return entities


# ── SNMP sweep (nmap XML) ────────────────────────────────────────────────────


def _parse_nmap_xml(raw: str) -> ET.Element | None:
    """Return parsed nmap XML root, or None on failure."""
    # Strip any trailing stderr noise before the XML
    xml_start = raw.find("<?xml")
    if xml_start == -1:
        xml_start = raw.find("<nmaprun")
    if xml_start == -1:
        return None
    try:
        return ET.fromstring(raw[xml_start:])
    except ET.ParseError:
        return None


def parse_snmp_sweep(raw: str, store: "TargetStore") -> list[dict]:
    """Parse nmap XML SNMP sweep — extract sysDescr/sysName per host."""
    entities: list[dict] = []
    root = _parse_nmap_xml(raw)
    if root is None:
        return entities

    for host in root.iter("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        # Only include hosts where UDP/161 was open
        port_el = host.find(".//port[@portid='161']")
        if port_el is None:
            continue
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") not in ("open", "open|filtered"):
            continue

        sys_descr = ""
        sys_name = ""
        community = ""

        # snmp-info script output
        for script in host.iter("script"):
            sid = script.get("id", "")
            if sid == "snmp-info":
                output = script.get("output", "")
                for elem in script.iter("elem"):
                    key = elem.get("key", "")
                    val = (elem.text or "").strip()
                    if key == "sysDescr":
                        sys_descr = val
                    elif key == "sysName":
                        sys_name = val
                    elif key == "Enterprise OID" or "community" in key.lower():
                        community = val
                # Fallback: parse plain-text output
                if not sys_descr:
                    for oline in output.splitlines():
                        if "sysDescr" in oline:
                            sys_descr = oline.split(":", 1)[-1].strip()
                        elif "sysName" in oline:
                            sys_name = oline.split(":", 1)[-1].strip()

        store.upsert_host(ip=ip, hostname=sys_name)
        entities.append(
            {
                "type": "snmp_device",
                "ip": ip,
                "sys_name": sys_name,
                "sys_descr": sys_descr,
                "community": community,
            }
        )
    return entities


# ── SMB discovery (nmap XML) ─────────────────────────────────────────────────


def parse_smb_discovery(raw: str, store: "TargetStore") -> list[dict]:
    """Parse nmap XML SMB discovery — flag SMBv1 as high-severity finding."""
    entities: list[dict] = []
    root = _parse_nmap_xml(raw)
    if root is None:
        return entities

    for host in root.iter("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        # Require at least one of 139/445 open
        open_ports = set()
        for port_el in host.iter("port"):
            pid = port_el.get("portid", "")
            st = port_el.find("state")
            if st is not None and st.get("state") == "open" and pid in ("139", "445"):
                open_ports.add(int(pid))
        if not open_ports:
            continue

        os_name = ""
        smb_security_mode = ""
        smb2_security_mode = ""
        smb_version = ""
        smbv1_enabled = False

        for script in host.iter("script"):
            sid = script.get("id", "")
            output = script.get("output", "")

            if sid == "smb-os-discovery":
                for elem in script.iter("elem"):
                    key = elem.get("key", "")
                    val = (elem.text or "").strip()
                    if key == "os":
                        os_name = val
                    elif "smb" in key.lower() and "version" in key.lower():
                        smb_version = val

                if not os_name:
                    for oline in output.splitlines():
                        if "OS:" in oline:
                            os_name = oline.split(":", 1)[-1].strip()

            elif sid == "smb-security-mode":
                smb_security_mode = output.strip()
                # SMBv1 is in use if this script ran and returned data
                if output and "message_signing" in output.lower():
                    smbv1_enabled = True

            elif sid == "smb2-security-mode":
                smb2_security_mode = output.strip()

        # Heuristic: if smb-security-mode script produced output,
        # SMBv1 is likely active (the script only fires on SMBv1 dialects)
        if smb_security_mode:
            smbv1_enabled = True

        store.upsert_host(ip=ip)
        entity: dict = {
            "type": "smb_host",
            "ip": ip,
            "os": os_name,
            "smb_version": smb_version,
            "smb_security_mode": smb_security_mode,
            "smb2_security_mode": smb2_security_mode,
            "open_ports": sorted(open_ports),
        }
        if smbv1_enabled:
            entity["finding"] = "SMBv1 enabled"
            entity["severity"] = "high"
        entities.append(entity)
    return entities


# ── mDNS enumeration (avahi-browse -p) ──────────────────────────────────────

# avahi-browse -p semicolon-separated line:
#   =;eth0;IPv4;Device Name;_http._tcp;local;hostname.local;192.168.1.5;80;
# Fields: sign ; iface ; proto ; name ; type ; domain ; hostname ; addr ; port ; txt
_AVAHI_RE = re.compile(
    r"^[=+]\s*;([^;]*);([^;]*);([^;]*);([^;]*);([^;]*);([^;]*);([^;]*);(\d*);?(.*)?$"
)


def parse_mdns_enum(raw: str, store: "TargetStore") -> list[dict]:
    """Parse avahi-browse -p output — return mdns_service entries per advertised service."""
    entities: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _AVAHI_RE.match(line)
        if not m:
            continue
        iface = m.group(1).strip()
        proto = m.group(2).strip()
        svc_name = m.group(3).strip()
        svc_type = m.group(4).strip()
        domain = m.group(5).strip()
        hostname = m.group(6).strip()
        addr = m.group(7).strip()
        port_str = m.group(8).strip()
        txt = m.group(9).strip() if m.lastindex and m.lastindex >= 9 else ""

        port = int(port_str) if port_str.isdigit() else 0

        if addr:
            store.upsert_host(ip=addr, hostname=hostname)

        entities.append(
            {
                "type": "mdns_service",
                "service_name": svc_name,
                "service_type": svc_type,
                "hostname": hostname,
                "ip": addr,
                "port": port,
                "interface": iface,
                "protocol": proto,
                "domain": domain,
                "txt": txt,
            }
        )
    return entities


# ── full_lan_sweep (structured JSON) ────────────────────────────────────────


def parse_full_lan_sweep(raw: str, store: "TargetStore") -> list[dict]:
    """Parse full_lan_sweep JSON output — combine ARP hosts + nmap detail."""
    entities: list[dict] = []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Fallback: extract any IP-like strings and build minimal host entries
        for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", raw):
            ip = m.group(1)
            if not ip.endswith(".0") and not ip.endswith(".255"):
                store.upsert_host(ip=ip)
                entities.append({"type": "lan_host", "ip": ip})
        return entities

    # Ingest ARP-discovered hosts
    for host in data.get("arp_hosts", []):
        ip = host.get("ip", "")
        mac = host.get("mac", "")
        vendor = host.get("vendor", "")
        if ip:
            store.upsert_host(ip=ip, mac=mac, vendor=vendor)
            entities.append(
                {
                    "type": "lan_host",
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "source": "arp_sweep",
                }
            )

    # Ingest nmap-enriched detail
    nmap_detail = data.get("nmap_detail", {})
    for host in nmap_detail.get("hosts", []):
        ip = host.get("ip", "")
        if not ip:
            continue
        os_name = host.get("os", "")
        services = host.get("services", [])
        store.upsert_host(ip=ip, os=os_name)
        entities.append(
            {
                "type": "lan_host_detail",
                "ip": ip,
                "os": os_name,
                "services": services,
                "source": "nmap_fingerprint",
            }
        )

    return entities


# ── registration ─────────────────────────────────────────────────────────────

PARSER_MAP[("lan_scan", "arp_sweep")] = parse_arp_sweep
PARSER_MAP[("lan_scan", "netdiscover")] = parse_netdiscover
PARSER_MAP[("lan_scan", "nbtscan")] = parse_nbtscan
PARSER_MAP[("lan_scan", "snmp_sweep")] = parse_snmp_sweep
PARSER_MAP[("lan_scan", "mdns_enum")] = parse_mdns_enum
PARSER_MAP[("lan_scan", "smb_discovery")] = parse_smb_discovery
PARSER_MAP[("lan_scan", "full_lan_sweep")] = parse_full_lan_sweep
