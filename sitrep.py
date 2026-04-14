"""Startup sitrep — one-shot probe of hardware, network, and engagement state.

Called once at server boot. Produces a Markdown status block injected into
the agent's system prompt so it knows what's online before the first turn.
"""

from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# USB vendor IDs to ignore when matching by fallback port.
# These are built-in controllers that happen to sit on ttyACM* paths.
_IGNORE_VIDS = {
    0x28DE,  # Valve Software (Steam Deck controller)
}


_BATTERY_LOW_THRESHOLD = 20  # percent — agent should warn user


def run_sitrep(
    engagement_config_path: str | Path = "config/engagement-config.json",
) -> str:
    """Run all probes and return a Markdown status block."""
    config = _load_config(engagement_config_path)
    if config is None:
        return ""

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    hostname = socket.gethostname()

    sections = [f"# System Status — {hostname} ({ts})"]
    sections.append(_probe_battery())
    sections.append(_probe_hardware(config.get("devices", {})))
    sections.append(_probe_network(config.get("devices", {}).get("wifi_adapter", {})))
    sections.append(_probe_engagement(config.get("engagement", {})))

    report = "\n\n".join(s for s in sections if s)
    logger.info("[sitrep] Startup probe complete")
    return report


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def _load_config(path: str | Path) -> Optional[dict]:
    p = Path(path)
    if not p.exists():
        logger.warning("[sitrep] Config not found: %s", p)
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("[sitrep] Failed to read config: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Battery probe
# ---------------------------------------------------------------------------


def _probe_battery() -> str:
    """Read battery level and charging status from sysfs."""
    bat_path = Path("/sys/class/power_supply")
    if not bat_path.exists():
        return ""

    # Find the first BAT* entry (Steam Deck uses BAT1)
    bat_dir = None
    for candidate in sorted(bat_path.iterdir()):
        if candidate.name.startswith("BAT"):
            bat_dir = candidate
            break

    if bat_dir is None:
        return ""

    try:
        capacity = int((bat_dir / "capacity").read_text().strip())
    except Exception:
        return ""

    try:
        status = (bat_dir / "status").read_text().strip()  # Charging, Discharging, Full, Not charging
    except Exception:
        status = "Unknown"

    if status == "Charging":
        icon = "🔌"
    elif status == "Full":
        icon = "🔋"
    elif capacity <= _BATTERY_LOW_THRESHOLD:
        icon = "🪫"
    else:
        icon = "🔋"

    warning = ""
    if status != "Charging" and capacity <= _BATTERY_LOW_THRESHOLD:
        warning = (
            f"\n\n> ⚠️ **LOW BATTERY** — {capacity}% remaining. "
            "Alert the user and consider conserving resources. "
            "Avoid long-running scans until the device is plugged in."
        )

    return f"## Battery\n| {icon} Level | Status |\n|--------|--------|\n| **{capacity}%** | {status} |{warning}"


# ---------------------------------------------------------------------------
# Hardware probe
# ---------------------------------------------------------------------------


def _probe_hardware(devices: dict) -> str:
    """Enumerate USB serial ports and match against configured devices."""
    usb_ports = _list_usb_ports()

    rows = []
    for name, cfg in devices.items():
        dev_type = cfg.get("type", "serial")
        if dev_type == "network":
            # Network devices checked in _probe_network
            continue

        sn = cfg.get("serial_number", "")
        fallback = cfg.get("fallback_port", "")

        # Match by serial number (authoritative) or fallback port (only if
        # the port is a real USB device — exclude built-in controllers like
        # the Steam Deck's ttyACM0).
        matched_port = None
        for port_info in usb_ports:
            if sn and port_info.get("serial_number") == sn:
                matched_port = port_info["device"]
                break
        if matched_port is None and fallback:
            for port_info in usb_ports:
                if port_info["device"] != fallback:
                    continue
                # Reject built-in / unrelated USB devices
                if port_info.get("vid") in _IGNORE_VIDS:
                    continue
                if not port_info.get("vid"):
                    continue  # no USB identity → not our device
                matched_port = port_info["device"]
                break

        if matched_port:
            rows.append(f"| {name} | ✅ detected | `{matched_port}` |")
        else:
            rows.append(f"| {name} | ❌ not found | — |")

    if not rows:
        return ""

    header = "## Hardware\n| Device | Status | Port |\n|--------|--------|------|"
    return header + "\n" + "\n".join(rows)


def _list_usb_ports() -> list[dict]:
    """List USB serial ports via pyserial."""
    try:
        from serial.tools.list_ports import comports

        return [
            {
                "device": p.device,
                "serial_number": p.serial_number or "",
                "description": p.description or "",
                "vid": p.vid,
                "pid": p.pid,
            }
            for p in comports()
        ]
    except Exception as exc:
        logger.warning("[sitrep] USB enumeration failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Network probe
# ---------------------------------------------------------------------------


def _probe_network(wifi_cfg: dict) -> str:
    """List network interfaces with addresses."""
    interfaces = _get_interfaces()
    if not interfaces:
        return ""

    wifi_iface = wifi_cfg.get("interface", "")
    monitor_iface = wifi_cfg.get("monitor_interface", "")

    rows = []
    found_tailscale = False
    found_wifi = False
    found_monitor = False

    for name, addrs in sorted(interfaces.items()):
        # Skip loopback
        if name == "lo" or name == "lo0":
            continue

        ipv4 = next((a for a in addrs if a.get("family") == "IPv4"), None)
        addr_str = ipv4["address"] if ipv4 else "—"

        notes = []
        if name.startswith("tailscale") or name.startswith("ts"):
            notes.append("tailscale")
            found_tailscale = True
        if name == monitor_iface:
            notes.append("monitor mode")
            found_monitor = True
        if name == wifi_iface:
            found_wifi = True

        note = f" ({', '.join(notes)})" if notes else ""
        rows.append(f"| {name} | {addr_str}{note} |")

    # Append WiFi adapter status if not found as an interface
    if wifi_iface and not found_wifi and not found_monitor:
        rows.append(f"| {wifi_iface} | ⚠ interface not found |")

    header = "## Network Interfaces\n| Interface | Address |\n|-----------|---------|"
    return header + "\n" + "\n".join(rows)


def _get_interfaces() -> dict:
    """Get network interfaces. Uses psutil if available, falls back to socket."""
    try:
        import psutil

        result = {}
        for name, addrs in psutil.net_if_addrs().items():
            result[name] = [
                {
                    "family": "IPv4" if a.family.name == "AF_INET" else a.family.name,
                    "address": a.address,
                }
                for a in addrs
            ]
        return result
    except ImportError:
        pass

    # Fallback: parse ip addr on Linux, ifconfig on macOS
    try:
        import subprocess

        result = {}
        out = subprocess.check_output(["ip", "-j", "addr"], timeout=5, text=True)
        for iface in json.loads(out):
            name = iface["ifname"]
            addrs = []
            for info in iface.get("addr_info", []):
                family = "IPv4" if info.get("family") == "inet" else info.get("family", "")
                addrs.append({"family": family, "address": info.get("local", "")})
            result[name] = addrs
        return result
    except Exception:
        pass

    return {}


# ---------------------------------------------------------------------------
# Engagement probe
# ---------------------------------------------------------------------------


def _probe_engagement(eng_cfg: dict) -> str:
    """Check for an active engagement session on disk."""
    workspace = Path(eng_cfg.get("workspace_dir", "/home/deck/engagements"))
    if not workspace.exists():
        return "## Engagement\nNo engagement workspace found."

    # Scan for the most recent engagement.json
    latest = None
    latest_time = None
    for ej in workspace.rglob("engagement.json"):
        try:
            data = json.loads(ej.read_text(encoding="utf-8"))
            # Active = has started_at but no ended_at
            if data.get("started_at") and not data.get("ended_at"):
                started = data["started_at"]
                if latest_time is None or started > latest_time:
                    latest = data
                    latest_time = started
        except Exception:
            continue

    if latest is None:
        return "## Engagement\nNo active engagement."

    findings_count = 0
    ws = Path(latest.get("workspace", ""))
    findings_file = ws / "findings.json"
    if findings_file.exists():
        try:
            findings_count = len(json.loads(findings_file.read_text(encoding="utf-8")))
        except Exception:
            pass

    return (
        f"## Active Engagement\n"
        f"| Field | Value |\n"
        f"|-------|-------|\n"
        f"| Name | {latest.get('name', '?')} |\n"
        f"| Scope | {latest.get('scope', 'N/A')} |\n"
        f"| Mode | **{latest.get('mode', '?')}** |\n"
        f"| Started | {latest.get('started_at', '?')} |\n"
        f"| Findings | {findings_count} |"
    )
