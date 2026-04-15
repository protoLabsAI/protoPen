"""Parser for iot_audit tool output — IoT device discovery and security assessment."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Version strings that suggest firmware exposure
_VERSION_RE = re.compile(
    r"(?:firmware|version|ver|v)[\s:/]+([\d][.\d]+[^\s]*)",
    re.IGNORECASE,
)

# Known insecure/management services on IoT devices
_HIGH_RISK_SERVICES = {
    "23": "Telnet",
    "2323": "Telnet (alt)",
    "21": "FTP",
    "502": "Modbus",
    "47808": "BACnet",
}


# ── Shared XML parser ──────────────────────────────────────────────────────────


def _parse_nmap_xml(
    raw: str,
    store: "TargetStore",
    *,
    action: str,
    tag_open_ports: bool = True,
) -> list[dict]:
    """Parse nmap XML output into structured entities and upsert hosts into the store."""
    entities: list[dict] = []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        # Non-XML output (e.g. tool not found, timeout) — return as-is
        if raw.strip():
            entities.append({"type": "raw", "action": action, "value": raw.strip()[:500]})
        return entities

    for host in root.findall(".//host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        ip = addr_el.get("addr", "") if addr_el is not None else ""

        mac_el = host.find("address[@addrtype='mac']")
        mac = mac_el.get("addr", "") if mac_el is not None else ""
        vendor = mac_el.get("vendor", "") if mac_el is not None else ""

        hostname_el = host.find(".//hostname[@type='PTR']")
        hostname = hostname_el.get("name", "") if hostname_el is not None else ""

        os_el = host.find(".//osmatch")
        os_name = os_el.get("name", "") if os_el is not None else ""

        if ip:
            tags = ["iot_scan"]
            if vendor:
                tags.append(f"vendor:{vendor}")
            store.upsert_host(ip=ip, mac=mac or None, hostname=hostname or None, tags=tags)

        for port_el in host.findall(".//port"):
            port_id = port_el.get("portid", "")
            proto = port_el.get("protocol", "tcp")
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""

            if state != "open":
                continue

            svc_el = port_el.find("service")
            svc_name = svc_el.get("name", "") if svc_el is not None else ""
            svc_product = svc_el.get("product", "") if svc_el is not None else ""
            svc_version = svc_el.get("version", "") if svc_el is not None else ""
            banner_parts = [p for p in (svc_product, svc_version) if p]
            banner = " ".join(banner_parts)

            # Collect NSE script output
            script_output = ""
            for script_el in port_el.findall("script"):
                script_output += script_el.get("output", "") + " "
            script_output = script_output.strip()

            service_entity: dict = {
                "type": "service",
                "ip": ip,
                "port": int(port_id) if port_id.isdigit() else port_id,
                "protocol": proto,
                "service": svc_name,
                "banner": banner[:200],
                "action": action,
            }
            if script_output:
                service_entity["script_output"] = script_output[:400]
            entities.append(service_entity)

            # ── Severity-rated findings ────────────────────────────────────────
            if port_id in _HIGH_RISK_SERVICES:
                svc_label = _HIGH_RISK_SERVICES[port_id]
                entities.append(
                    {
                        "type": "iot_finding",
                        "severity": "high",
                        "ip": ip,
                        "port": int(port_id),
                        "title": f"{svc_label} open on {ip}:{port_id}",
                        "detail": (
                            f"{svc_label} is enabled and reachable. "
                            f"Banner: {banner or 'none'}. "
                            "This service transmits credentials in cleartext and should be disabled."
                        ),
                        "action": action,
                    }
                )

            # HTTP default accounts hit
            if "http-default-accounts" in script_output.lower() and "credentials found" in script_output.lower():
                entities.append(
                    {
                        "type": "iot_finding",
                        "severity": "critical",
                        "ip": ip,
                        "port": int(port_id),
                        "title": f"Default credentials accepted on {ip}:{port_id}",
                        "detail": script_output[:500],
                        "action": action,
                    }
                )

            # Firmware version strings
            ver_match = _VERSION_RE.search(banner + " " + script_output)
            if ver_match:
                entities.append(
                    {
                        "type": "iot_finding",
                        "severity": "info",
                        "ip": ip,
                        "port": int(port_id),
                        "title": f"Firmware/version exposed on {ip}:{port_id}",
                        "detail": f"Version string: {ver_match.group(0)[:120]}",
                        "action": action,
                    }
                )

        # OS match
        if os_name and ip:
            entities.append(
                {
                    "type": "iot_finding",
                    "severity": "info",
                    "ip": ip,
                    "title": f"OS fingerprint: {os_name[:100]}",
                    "action": action,
                }
            )

    return entities


# ── Action-specific parsers ────────────────────────────────────────────────────


def parse_device_discovery(raw: str, store: "TargetStore") -> list[dict]:
    """Parse nmap device discovery sweep — tag all discovered hosts as IoT candidates."""
    return _parse_nmap_xml(raw, store, action="device_discovery")


def parse_fingerprint(raw: str, store: "TargetStore") -> list[dict]:
    """Parse deep fingerprint output — extract OS, services, banners."""
    return _parse_nmap_xml(raw, store, action="fingerprint")


def parse_telnet_check(raw: str, store: "TargetStore") -> list[dict]:
    """Parse telnet port scan — open Telnet is always a high-severity finding."""
    return _parse_nmap_xml(raw, store, action="telnet_check")


def parse_http_admin_check(raw: str, store: "TargetStore") -> list[dict]:
    """Parse HTTP admin panel scan — elevate any default-account hits to critical."""
    return _parse_nmap_xml(raw, store, action="http_admin_check")


def parse_mqtt_audit(raw: str, store: "TargetStore") -> list[dict]:
    """Parse mosquitto_sub output — any data returned = anonymous access confirmed."""
    entities: list[dict] = []
    raw = raw.strip()
    if not raw:
        # No output — either no broker, auth required, or connection refused
        entities.append(
            {
                "type": "iot_finding",
                "severity": "info",
                "title": "MQTT broker not reachable or authentication required",
                "detail": "mosquitto_sub returned no data — MQTT broker absent, firewalled, or auth enforced.",
                "action": "mqtt_audit",
            }
        )
        return entities

    # Data returned without credentials — unauthenticated access confirmed
    lines = [l for l in raw.splitlines() if l.strip()]
    broker_version = ""
    for line in lines:
        if "version" in line.lower():
            broker_version = line.strip()
            break

    entities.append(
        {
            "type": "iot_finding",
            "severity": "high",
            "title": "MQTT broker allows anonymous access",
            "detail": (
                f"mosquitto_sub connected and received {len(lines)} message(s) from $SYS/# "
                "without credentials. Broker information is publicly readable and any client "
                "may subscribe to device topics.\n"
                + (f"Broker version: {broker_version}\n" if broker_version else "")
                + f"Sample output:\n{raw[:400]}"
            ),
            "action": "mqtt_audit",
        }
    )

    # Extract IPs from broker output
    for ip in _IP_RE.findall(raw):
        store.upsert_host(ip=ip, tags=["mqtt_broker", "iot_scan"])

    return entities


def parse_snmp_audit(raw: str, store: "TargetStore") -> list[dict]:
    """Parse onesixtyone output — each line is a host that responded to community string."""
    entities: list[dict] = []
    raw = raw.strip()
    if not raw:
        return entities

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        # onesixtyone format: "192.168.1.1 [public] Linux router 5.4.0 ..."
        ip_match = _IP_RE.match(line)
        if not ip_match:
            continue

        ip = ip_match.group(1)
        community_match = re.search(r"\[([^\]]+)\]", line)
        community = community_match.group(1) if community_match else "unknown"
        sys_desc = line[line.find("]") + 1 :].strip() if "]" in line else line

        store.upsert_host(ip=ip, tags=["snmp_accessible", "iot_scan"])
        entities.append(
            {
                "type": "iot_finding",
                "severity": "medium",
                "ip": ip,
                "title": f"SNMP accessible with community string '{community}' on {ip}",
                "detail": (
                    f"SNMP responded to community string '{community}'. "
                    f"System description: {sys_desc[:200]}. "
                    "Default SNMP community strings expose device configuration, "
                    "routing tables, and interface details."
                ),
                "action": "snmp_audit",
            }
        )

    return entities


def parse_rtsp_discover(raw: str, store: "TargetStore") -> list[dict]:
    """Parse nmap rtsp-url-brute output — open RTSP streams, note auth status."""
    entities: list[dict] = []
    base = _parse_nmap_xml(raw, store, action="rtsp_discover")
    entities.extend(base)

    # Look for successful RTSP URL discoveries in script output
    for entity in base:
        script_out = entity.get("script_output", "")
        if not script_out:
            continue
        # nmap rtsp-url-brute reports discovered paths like "Discovered path: /live.sdp"
        if "discovered" in script_out.lower() or "200 OK" in script_out:
            ip = entity.get("ip", "")
            entities.append(
                {
                    "type": "iot_finding",
                    "severity": "medium",
                    "ip": ip,
                    "title": f"RTSP stream accessible on {ip}:554",
                    "detail": (
                        f"RTSP URL enumeration found accessible streams. "
                        f"Verify authentication is enforced.\nOutput: {script_out[:300]}"
                    ),
                    "action": "rtsp_discover",
                }
            )
            if ip:
                store.upsert_host(ip=ip, tags=["rtsp_camera", "iot_scan"])

    return entities


def parse_firmware_exposure(raw: str, store: "TargetStore") -> list[dict]:
    """Parse firmware banner grab — aggregate version strings."""
    return _parse_nmap_xml(raw, store, action="firmware_exposure")


def parse_default_creds(raw: str, store: "TargetStore") -> list[dict]:
    """Parse hydra default-credential spray output."""
    entities: list[dict] = []
    for line in raw.splitlines():
        # hydra successful login: "[22][ssh] host: 192.168.1.x   login: admin   password: admin"
        if "host:" in line and "login:" in line and "password:" in line:
            ip_match = re.search(r"host:\s*([\d.]+)", line)
            login_match = re.search(r"login:\s*(\S+)", line)
            pass_match = re.search(r"password:\s*(\S+)", line)
            port_match = re.search(r"\[(\d+)\]", line)

            ip = ip_match.group(1) if ip_match else ""
            login = login_match.group(1) if login_match else ""
            password = pass_match.group(1) if pass_match else ""
            port = port_match.group(1) if port_match else ""

            if ip:
                store.upsert_host(ip=ip, tags=["default_creds", "iot_scan"])

            entities.append(
                {
                    "type": "iot_finding",
                    "severity": "critical",
                    "ip": ip,
                    "port": int(port) if port.isdigit() else port,
                    "title": f"Default credentials accepted on {ip}:{port}",
                    "detail": (
                        f"Hydra confirmed login with default credentials: "
                        f"username='{login}', password='{password}'. "
                        "Device is fully compromised — change credentials immediately."
                    ),
                    "action": "default_creds",
                }
            )

    return entities


# ── Register all parsers ───────────────────────────────────────────────────────

PARSER_MAP[("iot_audit", "device_discovery")] = parse_device_discovery
PARSER_MAP[("iot_audit", "fingerprint")] = parse_fingerprint
PARSER_MAP[("iot_audit", "telnet_check")] = parse_telnet_check
PARSER_MAP[("iot_audit", "http_admin_check")] = parse_http_admin_check
PARSER_MAP[("iot_audit", "mqtt_audit")] = parse_mqtt_audit
PARSER_MAP[("iot_audit", "snmp_audit")] = parse_snmp_audit
PARSER_MAP[("iot_audit", "rtsp_discover")] = parse_rtsp_discover
PARSER_MAP[("iot_audit", "firmware_exposure")] = parse_firmware_exposure
PARSER_MAP[("iot_audit", "default_creds")] = parse_default_creds
