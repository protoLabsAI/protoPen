"""Target intelligence agent tool.

Wraps TargetStore as a nanobot/LangGraph-compatible Tool for the agent
to query, upsert, and analyze target data across all sensor domains.
"""
from __future__ import annotations

from typing import Any

try:
    from nanobot.agent.tools.base import Tool
except ImportError:
    from tools._tool_base import Tool

from knowledge.target_store import TargetStore


class TargetIntelTool(Tool):
    """Query and manage the target intelligence database."""

    def __init__(self, store: TargetStore):
        self._store = store

    @property
    def name(self) -> str:
        return "target_intel"

    @property
    def description(self) -> str:
        return (
            "Query and manage the target intelligence database. Tracks all discovered "
            "hosts, WiFi networks/stations, RF signals, BLE devices, RFID/NFC tags, "
            "open ports, and credentials across all sensor platforms (nmap, Marauder, "
            "Flipper Zero, PortaPack, aircrack-ng). Supports upsert (merge-on-conflict), "
            "subnet/prefix queries, temporal diff (what's new since last scan), and stats."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform",
                    "enum": [
                        "upsert_host", "query_hosts", "get_host",
                        "upsert_port",
                        "upsert_wifi_network", "upsert_wifi_station",
                        "add_rf_signal",
                        "upsert_ble_device",
                        "upsert_rfid_nfc_tag",
                        "add_credential",
                        "start_scan", "end_scan",
                        "stats", "diff",
                    ],
                },
                "ip": {"type": "string"},
                "mac": {"type": "string"},
                "hostname": {"type": "string"},
                "os": {"type": "string"},
                "vendor": {"type": "string"},
                "device_type": {"type": "string"},
                "host_id": {"type": "integer"},
                "port": {"type": "integer"},
                "protocol": {"type": "string"},
                "service": {"type": "string"},
                "banner": {"type": "string"},
                "bssid": {"type": "string"},
                "ssid": {"type": "string"},
                "channel": {"type": "integer"},
                "rssi": {"type": "integer"},
                "encryption": {"type": "string"},
                "frequency_hz": {"type": "integer"},
                "modulation": {"type": "string"},
                "data_hex": {"type": "string"},
                "source_device": {"type": "string"},
                "decoded_text": {"type": "string"},
                "name": {"type": "string"},
                "tag_type": {"type": "string"},
                "uid": {"type": "string"},
                "label": {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "hash_type": {"type": "string"},
                "source": {"type": "string"},
                "tool": {"type": "string"},
                "scan_action": {"type": "string", "description": "Tool action for start_scan"},
                "scan_session_id": {"type": "integer"},
                "engagement": {"type": "string"},
                "ip_prefix": {"type": "string"},
                "since": {"type": "string", "description": "ISO 8601 timestamp for diff"},
            },
            "required": ["action"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        dispatch = {
            "upsert_host": self._upsert_host,
            "query_hosts": self._query_hosts,
            "get_host": self._get_host,
            "upsert_port": self._upsert_port,
            "upsert_wifi_network": self._upsert_wifi_network,
            "upsert_wifi_station": self._upsert_wifi_station,
            "add_rf_signal": self._add_rf_signal,
            "upsert_ble_device": self._upsert_ble_device,
            "upsert_rfid_nfc_tag": self._upsert_rfid_nfc_tag,
            "add_credential": self._add_credential,
            "start_scan": self._start_scan,
            "end_scan": self._end_scan,
            "stats": self._stats,
            "diff": self._diff,
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            return fn(kwargs)
        except Exception as exc:
            return f"TargetIntel error ({action}): {exc}"

    def _upsert_host(self, kw: dict) -> str:
        hid = self._store.upsert_host(
            ip=kw.get("ip", ""), mac=kw.get("mac", ""),
            hostname=kw.get("hostname", ""), os=kw.get("os", ""),
            vendor=kw.get("vendor", ""), device_type=kw.get("device_type", "unknown"),
        )
        host = self._store.get_host(hid)
        return f"Host upserted (id={hid}): {host['ip'] or host['mac']}"

    def _query_hosts(self, kw: dict) -> str:
        hosts = self._store.query_hosts(
            ip_prefix=kw.get("ip_prefix", ""),
            device_type=kw.get("device_type", ""),
            since=kw.get("since", ""),
        )
        if not hosts:
            return "No hosts found matching query."
        lines = [f"Found {len(hosts)} host(s):"]
        for h in hosts:
            ports_count = len(self._store.get_ports(h["id"]))
            lines.append(
                f"  [{h['id']}] {h['ip'] or '?'} / {h['mac'] or '?'} "
                f"— {h['hostname'] or '?'} ({h['device_type']}) "
                f"ports={ports_count} last_seen={h['last_seen']}"
            )
        return "\n".join(lines)

    def _get_host(self, kw: dict) -> str:
        hid = kw.get("host_id", 0)
        host = self._store.get_host(hid)
        if not host:
            return f"Host {hid} not found."
        ports = self._store.get_ports(hid)
        lines = [
            f"Host #{hid}:",
            f"  IP: {host['ip'] or 'N/A'}",
            f"  MAC: {host['mac'] or 'N/A'}",
            f"  Hostname: {host['hostname'] or 'N/A'}",
            f"  OS: {host['os'] or 'N/A'}",
            f"  Type: {host['device_type']}",
            f"  First seen: {host['first_seen']}",
            f"  Last seen: {host['last_seen']}",
        ]
        if ports:
            lines.append(f"  Ports ({len(ports)}):")
            for p in ports:
                lines.append(f"    {p['port']}/{p['protocol']} {p['state']} {p['service'] or ''}")
        return "\n".join(lines)

    def _upsert_port(self, kw: dict) -> str:
        pid = self._store.upsert_port(
            host_id=kw["host_id"], port=kw["port"],
            protocol=kw.get("protocol", "tcp"),
            service=kw.get("service", ""), banner=kw.get("banner", ""),
        )
        return f"Port upserted (id={pid}): {kw['port']}/{kw.get('protocol', 'tcp')}"

    def _upsert_wifi_network(self, kw: dict) -> str:
        nid = self._store.upsert_wifi_network(
            bssid=kw["bssid"], ssid=kw.get("ssid", ""),
            channel=kw.get("channel", 0), rssi=kw.get("rssi", 0),
            encryption=kw.get("encryption", ""),
        )
        return f"WiFi network upserted (id={nid}): {kw.get('ssid', '')} [{kw['bssid']}]"

    def _upsert_wifi_station(self, kw: dict) -> str:
        sid = self._store.upsert_wifi_station(mac=kw["mac"], rssi=kw.get("rssi", 0))
        return f"WiFi station upserted (id={sid}): {kw['mac']}"

    def _add_rf_signal(self, kw: dict) -> str:
        rid = self._store.add_rf_signal(
            frequency_hz=kw["frequency_hz"],
            modulation=kw.get("modulation", ""),
            protocol=kw.get("protocol", ""),
            data_hex=kw.get("data_hex", ""),
            source_device=kw.get("source_device", ""),
            decoded_text=kw.get("decoded_text", ""),
        )
        freq_mhz = kw["frequency_hz"] / 1_000_000
        return f"RF signal recorded (id={rid}): {freq_mhz:.3f} MHz {kw.get('protocol', '')}"

    def _upsert_ble_device(self, kw: dict) -> str:
        bid = self._store.upsert_ble_device(
            mac=kw["mac"], name=kw.get("name", ""),
            rssi=kw.get("rssi", 0),
        )
        return f"BLE device upserted (id={bid}): {kw.get('name', '')} [{kw['mac']}]"

    def _upsert_rfid_nfc_tag(self, kw: dict) -> str:
        tid = self._store.upsert_rfid_nfc_tag(
            tag_type=kw["tag_type"], uid=kw["uid"],
            label=kw.get("label", ""),
        )
        return f"RFID/NFC tag upserted (id={tid}): {kw['tag_type']} {kw['uid']}"

    def _add_credential(self, kw: dict) -> str:
        cid = self._store.add_credential(
            username=kw.get("username", ""), password=kw.get("password", ""),
            hash_type=kw.get("hash_type", ""), source=kw.get("source", ""),
            host_id=kw.get("host_id", 0),
            wifi_network_id=kw.get("wifi_network_id", 0),
        )
        return f"Credential recorded (id={cid}): {kw.get('username', '?')} from {kw.get('source', '?')}"

    def _start_scan(self, kw: dict) -> str:
        sid = self._store.create_scan_session(
            tool=kw.get("tool", ""), action=kw.get("scan_action", ""),
            engagement=kw.get("engagement", ""),
        )
        return f"Scan session started (id={sid})"

    def _end_scan(self, kw: dict) -> str:
        self._store.end_scan_session(kw.get("scan_session_id", 0))
        return "Scan session ended."

    def _stats(self, _kw: dict) -> str:
        stats = self._store.get_stats()
        lines = ["Target Intelligence Stats:"]
        for table, count in stats.items():
            lines.append(f"  {table}: {count}")
        return "\n".join(lines)

    def _diff(self, kw: dict) -> str:
        since = kw.get("since", "")
        if not since:
            return "Required: 'since' (ISO 8601 timestamp)"
        diff = self._store.diff_since(since)
        lines = [f"Changes since {since}:"]
        for key, count in diff.items():
            if count > 0:
                lines.append(f"  {key}: +{count}")
        if len(lines) == 1:
            lines.append("  No new entities.")
        return "\n".join(lines)
