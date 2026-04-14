"""Persistent target intelligence store for protoPen.

Tracks hosts, WiFi networks/stations, RF signals, BLE devices, RFID/NFC tags,
open ports, and credentials across all sensor platforms.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = "/sandbox/knowledge/targets.db"
_SCHEMA_PATH = Path(__file__).parent / "target_schema.sql"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_mac(mac: str) -> str:
    """Normalize MAC to uppercase colon-separated."""
    if not mac:
        return ""
    clean = mac.upper().replace("-", ":").replace(".", ":")
    # Handle Cisco-style aabb.ccdd.eeff
    if len(clean) == 14 and ":" not in mac and "." in mac:
        h = clean.replace(":", "")
        clean = ":".join(h[i : i + 2] for i in range(0, 12, 2))
    return clean


class TargetStore:
    """SQLite-backed persistent store for target intelligence."""

    def __init__(self, db_path: str = _DEFAULT_DB_PATH):
        self._db_path = db_path
        self._db: Optional[sqlite3.Connection] = None

    def _get_db(self) -> sqlite3.Connection:
        if self._db is not None:
            return self._db
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self._db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        schema_sql = _SCHEMA_PATH.read_text()
        self._db.executescript(schema_sql)
        return self._db

    # ── Scan Sessions ──────────────────────────────────────────────

    def create_scan_session(
        self,
        tool: str,
        action: str,
        engagement: str = "",
        notes: str = "",
    ) -> int:
        db = self._get_db()
        cur = db.execute(
            "INSERT INTO scan_sessions (engagement, tool, action, started_at, notes) VALUES (?, ?, ?, ?, ?)",
            (engagement, tool, action, _now(), notes),
        )
        db.commit()
        return cur.lastrowid

    def end_scan_session(self, session_id: int, raw_output: str = ""):
        db = self._get_db()
        db.execute(
            "UPDATE scan_sessions SET ended_at = ?, raw_output = ? WHERE id = ?",
            (_now(), raw_output, session_id),
        )
        db.commit()

    def get_scan_session(self, session_id: int) -> dict | None:
        db = self._get_db()
        row = db.execute("SELECT * FROM scan_sessions WHERE id = ?", (session_id,)).fetchone()
        return dict(row) if row else None

    # ── Hosts ──────────────────────────────────────────────────────

    def upsert_host(
        self,
        ip: str = "",
        mac: str = "",
        hostname: str = "",
        os: str = "",
        vendor: str = "",
        device_type: str = "unknown",
        tags: list[str] | None = None,
        scan_session_id: int = 0,
        notes: str = "",
    ) -> int:
        mac = _normalize_mac(mac)
        now = _now()
        db = self._get_db()

        # Try to find existing by IP+MAC match
        existing = None
        if ip and mac:
            existing = db.execute(
                "SELECT id FROM hosts WHERE ip = ? AND mac = ?",
                (ip, mac),
            ).fetchone()
        elif ip:
            existing = db.execute(
                "SELECT id FROM hosts WHERE ip = ? AND (mac = '' OR mac IS NULL)",
                (ip,),
            ).fetchone()
        elif mac:
            existing = db.execute(
                "SELECT id FROM hosts WHERE mac = ? AND (ip = '' OR ip IS NULL)",
                (mac,),
            ).fetchone()

        if existing:
            host_id = existing["id"]
            updates = ["last_seen = ?"]
            params: list[Any] = [now]
            if hostname:
                updates.append("hostname = ?")
                params.append(hostname)
            if os:
                updates.append("os = ?")
                params.append(os)
            if vendor:
                updates.append("vendor = ?")
                params.append(vendor)
            if device_type != "unknown":
                updates.append("device_type = ?")
                params.append(device_type)
            if tags:
                updates.append("tags = ?")
                params.append(json.dumps(tags))
            if scan_session_id:
                updates.append("scan_session_id = ?")
                params.append(scan_session_id)
            if notes:
                updates.append("notes = ?")
                params.append(notes)
            params.append(host_id)
            db.execute(f"UPDATE hosts SET {', '.join(updates)} WHERE id = ?", params)
            db.commit()
            return host_id

        cur = db.execute(
            "INSERT INTO hosts (ip, mac, hostname, os, vendor, device_type, tags, "
            "first_seen, last_seen, scan_session_id, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(ip, mac) DO UPDATE SET "
            "last_seen = excluded.last_seen, "
            "hostname = COALESCE(NULLIF(excluded.hostname, ''), hosts.hostname), "
            "os = COALESCE(NULLIF(excluded.os, ''), hosts.os), "
            "vendor = COALESCE(NULLIF(excluded.vendor, ''), hosts.vendor), "
            "device_type = CASE WHEN excluded.device_type != 'unknown' "
            "  THEN excluded.device_type ELSE hosts.device_type END, "
            "scan_session_id = COALESCE(excluded.scan_session_id, hosts.scan_session_id)",
            (
                ip,
                mac,
                hostname,
                os,
                vendor,
                device_type,
                json.dumps(tags or []),
                now,
                now,
                scan_session_id or None,
                notes,
            ),
        )
        db.commit()
        return cur.lastrowid

    def get_host(self, host_id: int) -> dict | None:
        db = self._get_db()
        row = db.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        return dict(row) if row else None

    def query_hosts(
        self,
        ip_prefix: str = "",
        mac_prefix: str = "",
        device_type: str = "",
        since: str = "",
    ) -> list[dict]:
        db = self._get_db()
        clauses = []
        params: list[Any] = []
        if ip_prefix:
            clauses.append("ip LIKE ?")
            params.append(f"{ip_prefix}%")
        if mac_prefix:
            clauses.append("mac LIKE ?")
            params.append(f"{_normalize_mac(mac_prefix)}%")
        if device_type:
            clauses.append("device_type = ?")
            params.append(device_type)
        if since:
            clauses.append("last_seen >= ?")
            params.append(since)
        where = " AND ".join(clauses) if clauses else "1=1"
        rows = db.execute(f"SELECT * FROM hosts WHERE {where} ORDER BY last_seen DESC", params).fetchall()
        return [dict(r) for r in rows]

    # ── Ports ──────────────────────────────────────────────────────

    def upsert_port(
        self,
        host_id: int,
        port: int,
        protocol: str = "tcp",
        state: str = "open",
        service: str = "",
        banner: str = "",
        scan_session_id: int = 0,
    ) -> int:
        now = _now()
        db = self._get_db()
        existing = db.execute(
            "SELECT id FROM ports WHERE host_id = ? AND port = ? AND protocol = ?",
            (host_id, port, protocol),
        ).fetchone()
        if existing:
            pid = existing["id"]
            updates = ["last_seen = ?", "state = ?"]
            params: list[Any] = [now, state]
            if service:
                updates.append("service = ?")
                params.append(service)
            if banner:
                updates.append("banner = ?")
                params.append(banner)
            if scan_session_id:
                updates.append("scan_session_id = ?")
                params.append(scan_session_id)
            params.append(pid)
            db.execute(f"UPDATE ports SET {', '.join(updates)} WHERE id = ?", params)
            db.commit()
            return pid
        cur = db.execute(
            "INSERT INTO ports (host_id, port, protocol, state, service, banner, "
            "first_seen, last_seen, scan_session_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (host_id, port, protocol, state, service, banner, now, now, scan_session_id or None),
        )
        db.commit()
        return cur.lastrowid

    def get_ports(self, host_id: int) -> list[dict]:
        db = self._get_db()
        rows = db.execute(
            "SELECT * FROM ports WHERE host_id = ? ORDER BY port",
            (host_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── WiFi Networks ──────────────────────────────────────────────

    def upsert_wifi_network(
        self,
        bssid: str,
        ssid: str = "",
        channel: int = 0,
        rssi: int = 0,
        encryption: str = "",
        wps: bool = False,
        host_id: int = 0,
        scan_session_id: int = 0,
        notes: str = "",
    ) -> int:
        bssid = _normalize_mac(bssid)
        now = _now()
        db = self._get_db()
        existing = db.execute(
            "SELECT id FROM wifi_networks WHERE bssid = ?",
            (bssid,),
        ).fetchone()
        if existing:
            nid = existing["id"]
            updates = ["last_seen = ?"]
            params: list[Any] = [now]
            if ssid:
                updates.append("ssid = ?")
                params.append(ssid)
            if channel:
                updates.append("channel = ?")
                params.append(channel)
            if rssi:
                updates.append("rssi = ?")
                params.append(rssi)
            if encryption:
                updates.append("encryption = ?")
                params.append(encryption)
            if scan_session_id:
                updates.append("scan_session_id = ?")
                params.append(scan_session_id)
            params.append(nid)
            db.execute(f"UPDATE wifi_networks SET {', '.join(updates)} WHERE id = ?", params)
            db.commit()
            return nid
        cur = db.execute(
            "INSERT INTO wifi_networks (bssid, ssid, channel, rssi, encryption, wps, "
            "host_id, first_seen, last_seen, scan_session_id, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                bssid,
                ssid,
                channel,
                rssi,
                encryption,
                int(wps),
                host_id or None,
                now,
                now,
                scan_session_id or None,
                notes,
            ),
        )
        db.commit()
        return cur.lastrowid

    # ── WiFi Stations ──────────────────────────────────────────────

    def upsert_wifi_station(
        self,
        mac: str,
        network_id: int = 0,
        rssi: int = 0,
        probed_ssids: list[str] | None = None,
        host_id: int = 0,
        scan_session_id: int = 0,
    ) -> int:
        mac = _normalize_mac(mac)
        now = _now()
        db = self._get_db()
        existing = db.execute(
            "SELECT id FROM wifi_stations WHERE mac = ?",
            (mac,),
        ).fetchone()
        if existing:
            sid = existing["id"]
            updates = ["last_seen = ?"]
            params: list[Any] = [now]
            if network_id:
                updates.append("network_id = ?")
                params.append(network_id)
            if rssi:
                updates.append("rssi = ?")
                params.append(rssi)
            if probed_ssids:
                updates.append("probed_ssids = ?")
                params.append(json.dumps(probed_ssids))
            if scan_session_id:
                updates.append("scan_session_id = ?")
                params.append(scan_session_id)
            params.append(sid)
            db.execute(f"UPDATE wifi_stations SET {', '.join(updates)} WHERE id = ?", params)
            db.commit()
            return sid
        cur = db.execute(
            "INSERT INTO wifi_stations (mac, network_id, rssi, probed_ssids, host_id, "
            "first_seen, last_seen, scan_session_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                mac,
                network_id or None,
                rssi,
                json.dumps(probed_ssids or []),
                host_id or None,
                now,
                now,
                scan_session_id or None,
            ),
        )
        db.commit()
        return cur.lastrowid

    # ── RF Signals ─────────────────────────────────────────────────

    def add_rf_signal(
        self,
        frequency_hz: int,
        modulation: str = "",
        protocol: str = "",
        data_hex: str = "",
        signal_strength: int = 0,
        source_device: str = "",
        capture_file: str = "",
        decoded_text: str = "",
        scan_session_id: int = 0,
        notes: str = "",
    ) -> int:
        now = _now()
        db = self._get_db()
        cur = db.execute(
            "INSERT INTO rf_signals (frequency_hz, modulation, protocol, data_hex, "
            "signal_strength, source_device, capture_file, decoded_text, "
            "first_seen, last_seen, scan_session_id, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                frequency_hz,
                modulation,
                protocol,
                data_hex,
                signal_strength,
                source_device,
                capture_file,
                decoded_text,
                now,
                now,
                scan_session_id or None,
                notes,
            ),
        )
        db.commit()
        return cur.lastrowid

    # ── BLE Devices ────────────────────────────────────────────────

    def upsert_ble_device(
        self,
        mac: str,
        name: str = "",
        address_type: str = "public",
        rssi: int = 0,
        services: list[str] | None = None,
        manufacturer_data: str = "",
        host_id: int = 0,
        scan_session_id: int = 0,
    ) -> int:
        mac = _normalize_mac(mac)
        now = _now()
        db = self._get_db()
        existing = db.execute(
            "SELECT id FROM ble_devices WHERE mac = ?",
            (mac,),
        ).fetchone()
        if existing:
            bid = existing["id"]
            updates = ["last_seen = ?"]
            params: list[Any] = [now]
            if name:
                updates.append("name = ?")
                params.append(name)
            if rssi:
                updates.append("rssi = ?")
                params.append(rssi)
            if services:
                updates.append("services = ?")
                params.append(json.dumps(services))
            if scan_session_id:
                updates.append("scan_session_id = ?")
                params.append(scan_session_id)
            params.append(bid)
            db.execute(f"UPDATE ble_devices SET {', '.join(updates)} WHERE id = ?", params)
            db.commit()
            return bid
        cur = db.execute(
            "INSERT INTO ble_devices (mac, name, address_type, rssi, services, "
            "manufacturer_data, host_id, first_seen, last_seen, scan_session_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                mac,
                name,
                address_type,
                rssi,
                json.dumps(services or []),
                manufacturer_data,
                host_id or None,
                now,
                now,
                scan_session_id or None,
            ),
        )
        db.commit()
        return cur.lastrowid

    # ── RFID / NFC Tags ───────────────────────────────────────────

    def upsert_rfid_nfc_tag(
        self,
        tag_type: str,
        uid: str,
        protocol: str = "",
        atqa: str = "",
        sak: str = "",
        data_hex: str = "",
        label: str = "",
        scan_session_id: int = 0,
        notes: str = "",
    ) -> int:
        now = _now()
        db = self._get_db()
        existing = db.execute(
            "SELECT id FROM rfid_nfc_tags WHERE tag_type = ? AND uid = ?",
            (tag_type, uid),
        ).fetchone()
        if existing:
            tid = existing["id"]
            updates = ["last_seen = ?"]
            params: list[Any] = [now]
            if label:
                updates.append("label = ?")
                params.append(label)
            if data_hex:
                updates.append("data_hex = ?")
                params.append(data_hex)
            if scan_session_id:
                updates.append("scan_session_id = ?")
                params.append(scan_session_id)
            if notes:
                updates.append("notes = ?")
                params.append(notes)
            params.append(tid)
            db.execute(f"UPDATE rfid_nfc_tags SET {', '.join(updates)} WHERE id = ?", params)
            db.commit()
            return tid
        cur = db.execute(
            "INSERT INTO rfid_nfc_tags (tag_type, uid, protocol, atqa, sak, data_hex, "
            "label, first_seen, last_seen, scan_session_id, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tag_type, uid, protocol, atqa, sak, data_hex, label, now, now, scan_session_id or None, notes),
        )
        db.commit()
        return cur.lastrowid

    # ── Credentials ────────────────────────────────────────────────

    def add_credential(
        self,
        username: str = "",
        password: str = "",
        hash_type: str = "",
        cracked: bool = False,
        source: str = "",
        host_id: int = 0,
        wifi_network_id: int = 0,
        scan_session_id: int = 0,
        notes: str = "",
    ) -> int:
        now = _now()
        db = self._get_db()
        cur = db.execute(
            "INSERT INTO credentials (username, password, hash_type, cracked, source, "
            "host_id, wifi_network_id, first_seen, scan_session_id, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                username,
                password,
                hash_type,
                int(cracked),
                source,
                host_id or None,
                wifi_network_id or None,
                now,
                scan_session_id or None,
                notes,
            ),
        )
        db.commit()
        return cur.lastrowid

    # ── Stats & Diff ───────────────────────────────────────────────

    def get_stats(self) -> dict:
        db = self._get_db()
        tables = [
            "hosts",
            "ports",
            "wifi_networks",
            "wifi_stations",
            "rf_signals",
            "ble_devices",
            "rfid_nfc_tags",
            "credentials",
            "scan_sessions",
        ]
        stats = {}
        for table in tables:
            row = db.execute(f"SELECT COUNT(*) as cnt FROM {table}").fetchone()
            stats[table] = row["cnt"]
        return stats

    def diff_since(self, since: str) -> dict:
        """Return counts of new entities discovered since a timestamp."""
        db = self._get_db()
        diff = {}
        for table, col in [
            ("hosts", "first_seen"),
            ("ports", "first_seen"),
            ("wifi_networks", "first_seen"),
            ("wifi_stations", "first_seen"),
            ("rf_signals", "first_seen"),
            ("ble_devices", "first_seen"),
            ("rfid_nfc_tags", "first_seen"),
            ("credentials", "first_seen"),
        ]:
            row = db.execute(
                f"SELECT COUNT(*) as cnt FROM {table} WHERE {col} >= ?",
                (since,),
            ).fetchone()
            diff[f"new_{table}"] = row["cnt"]
        return diff

    def close(self):
        if self._db:
            self._db.close()
            self._db = None
