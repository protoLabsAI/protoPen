"""WiFi Marauder serial bridge tool.

Wraps all ESP32 Marauder CLI commands accessible over USB serial.
"""

from __future__ import annotations

from typing import Any

try:
    from nanobot.tool import Tool
except ImportError:
    from tools._tool_base import Tool

from tools.device_manager import DeviceConnection

_LIST_FLAGS: dict[str, str] = {
    "aps": "-a",
    "stations": "-c",
    "ssids": "-s",
}


class MarauderTool(Tool):
    """Serial bridge for the ESP32 WiFi Marauder firmware."""

    def __init__(self, conn: DeviceConnection) -> None:
        self._conn = conn

    # ── Tool interface ─────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "marauder"

    @property
    def description(self) -> str:
        return (
            "WiFi Marauder serial bridge. Provides access to WiFi scanning, "
            "attacks, sniffing, BLE spam, evil portal, karma, and SSID "
            "management via USB serial to the ESP32 Marauder firmware."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Method to invoke on the Marauder.",
                    "enum": [
                        "scan_aps", "scan_stations", "stop", "list_results",
                        "select_targets", "select_all", "set_channel", "clear_list",
                        "deauth", "beacon_spam", "probe_flood", "rickroll",
                        "sniff_pmkid", "sniff_deauth", "sniff_beacon", "sniff_raw",
                        "bt_spam_all", "sour_apple", "swift_pair", "samsung_ble_spam",
                        "evil_portal", "karma", "ssid_add", "ssid_generate",
                        "info", "send_command",
                    ],
                },
                "kind": {"type": "string", "description": "Result kind: aps, stations, ssids."},
                "indices": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Target indices for select_targets.",
                },
                "ch": {"type": "integer", "description": "WiFi channel number."},
                "deauth": {"type": "boolean", "description": "Send deauth during PMKID sniff."},
                "html_path": {"type": "string", "description": "Path to evil portal HTML on SD."},
                "name": {"type": "string", "description": "SSID name for ssid_add."},
                "count": {"type": "integer", "description": "Number of SSIDs to generate."},
                "cmd": {"type": "string", "description": "Raw CLI command."},
            },
            "required": ["action"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        dispatch = {
            "scan_aps": lambda: self.scan_aps(),
            "scan_stations": lambda: self.scan_stations(),
            "stop": lambda: self.stop(),
            "list_results": lambda: self.list_results(kwargs.get("kind", "aps")),
            "select_targets": lambda: self.select_targets(kwargs.get("indices", [])),
            "select_all": lambda: self.select_all(),
            "set_channel": lambda: self.set_channel(kwargs["ch"]),
            "clear_list": lambda: self.clear_list(),
            "deauth": lambda: self.deauth(),
            "beacon_spam": lambda: self.beacon_spam(),
            "probe_flood": lambda: self.probe_flood(),
            "rickroll": lambda: self.rickroll(),
            "sniff_pmkid": lambda: self.sniff_pmkid(deauth=kwargs.get("deauth", False)),
            "sniff_deauth": lambda: self.sniff_deauth(),
            "sniff_beacon": lambda: self.sniff_beacon(),
            "sniff_raw": lambda: self.sniff_raw(),
            "bt_spam_all": lambda: self.bt_spam_all(),
            "sour_apple": lambda: self.sour_apple(),
            "swift_pair": lambda: self.swift_pair(),
            "samsung_ble_spam": lambda: self.samsung_ble_spam(),
            "evil_portal": lambda: self.evil_portal(html_path=kwargs.get("html_path")),
            "karma": lambda: self.karma(),
            "ssid_add": lambda: self.ssid_add(kwargs["name"]),
            "ssid_generate": lambda: self.ssid_generate(kwargs["count"]),
            "info": lambda: self.info(),
            "send_command": lambda: self.send_command(kwargs["cmd"]),
        }
        handler = dispatch.get(action)
        if handler is None:
            return f"Unknown action: {action}"
        return handler()

    # ── Scanning ───────────────────────────────────────────────────

    def scan_aps(self) -> str:
        return self._conn.send("scanap")

    def scan_stations(self) -> str:
        return self._conn.send("scansta")

    def stop(self) -> str:
        return self._conn.send("stopscan")

    def list_results(self, kind: str = "aps") -> str:
        flag = _LIST_FLAGS.get(kind, "-a")
        return self._conn.send(f"list {flag}")

    def select_targets(self, indices: list[int] | None) -> str:
        if not indices:
            return "No indices provided."
        joined = ",".join(str(i) for i in indices)
        return self._conn.send(f"select -a {joined}")

    def select_all(self) -> str:
        return self._conn.send("select -a all")

    def set_channel(self, ch: int) -> str:
        return self._conn.send(f"channel {ch}")

    def clear_list(self) -> str:
        return self._conn.send("clearlist")

    # ── Attacks ────────────────────────────────────────────────────

    def deauth(self) -> str:
        return self._conn.send("attack -t deauth")

    def beacon_spam(self) -> str:
        return self._conn.send("attack -t beacon -l")

    def probe_flood(self) -> str:
        return self._conn.send("attack -t probe")

    def rickroll(self) -> str:
        return self._conn.send("attack -t rickroll")

    # ── Sniffing ───────────────────────────────────────────────────

    def sniff_pmkid(self, deauth: bool = False) -> str:
        cmd = "sniffpmkid"
        if deauth:
            cmd += " -d"
        return self._conn.send(cmd)

    def sniff_deauth(self) -> str:
        return self._conn.send("sniffdeauth")

    def sniff_beacon(self) -> str:
        return self._conn.send("sniffbeacon")

    def sniff_raw(self) -> str:
        return self._conn.send("sniffraw")

    # ── BLE ────────────────────────────────────────────────────────

    def bt_spam_all(self) -> str:
        return self._conn.send("blespam")

    def sour_apple(self) -> str:
        return self._conn.send("sourapple")

    def swift_pair(self) -> str:
        return self._conn.send("swiftpair")

    def samsung_ble_spam(self) -> str:
        return self._conn.send("samsungblespam")

    # ── Advanced ───────────────────────────────────────────────────

    def evil_portal(self, html_path: str | None = None) -> str:
        cmd = "evilportal"
        if html_path:
            cmd += f" {html_path}"
        return self._conn.send(cmd)

    def karma(self) -> str:
        return self._conn.send("karma")

    def ssid_add(self, name: str) -> str:
        return self._conn.send(f'ssid -a -n "{name}"')

    def ssid_generate(self, count: int) -> str:
        return self._conn.send(f"ssid -a -g {count}")

    # ── System ─────────────────────────────────────────────────────

    def info(self) -> str:
        return self._conn.send("info")

    def send_command(self, cmd: str) -> str:
        return self._conn.send(cmd)
