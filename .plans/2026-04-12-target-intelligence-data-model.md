# Target Intelligence Data Model — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a persistent, cross-sensor target intelligence system to protoPen that unifies hosts, WiFi APs/stations, RF signals, RFID/NFC/BLE devices, and engagement findings into a single queryable SQLite schema with temporal tracking and cross-domain correlation.

**Architecture:** Extend the existing `knowledge/` package with a new `target_store.py` module and `target_schema.sql` DDL. The target DB is a *separate* SQLite file (`/sandbox/knowledge/targets.db`) from `research.db` — different domain, different lifecycle. Eight core tables follow a hub-and-spoke model: `hosts` is the central entity with satellite tables for `wifi_networks`, `wifi_stations`, `rf_signals`, `ble_devices`, `rfid_nfc_tags`, `ports`, and `credentials`. A `scan_sessions` table provides temporal context. All tables share a `first_seen`/`last_seen` pattern for temporal tracking. A new `TargetIntelTool` wraps the store as an agent tool. The engagement manager auto-upserts hosts when findings are logged.

**Tech Stack:** Python 3.12, sqlite3 (stdlib), dataclasses, pytest

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `knowledge/target_schema.sql` | Create | DDL for all 8 target tables + indexes |
| `knowledge/target_models.py` | Create | Dataclasses for Host, WifiNetwork, WifiStation, RfSignal, BleDevice, RfidNfcTag, Port, Credential, ScanSession |
| `knowledge/target_store.py` | Create | `TargetStore` class — CRUD, upsert, query, diff, stats |
| `tools/target_intel.py` | Create | `TargetIntelTool` — agent tool wrapping TargetStore |
| `tools/engagement.py` | Modify | Auto-upsert hosts when findings are logged |
| `server.py` | Modify | Wire `TargetStore` singleton, inject into agent tools |
| `tests/test_target_store.py` | Create | Unit tests for TargetStore |
| `tests/test_target_intel.py` | Create | Unit tests for TargetIntelTool |
| `tests/test_engagement_autoupsert.py` | Create | Tests for engagement → target_store integration |

---

### Task 1: DDL — `knowledge/target_schema.sql`

**Files:**
- Create: `knowledge/target_schema.sql`

- [ ] **Step 1: Write the schema file**

```sql
-- protoPen target intelligence schema
-- Unified multi-sensor target tracking for pentest engagements

-- Scan sessions: temporal grouping for every scan/capture operation
CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement TEXT,                          -- engagement name (nullable if ad-hoc)
    tool TEXT NOT NULL,                       -- 'nmap', 'marauder', 'flipper', 'portapack', 'blackarch'
    action TEXT NOT NULL,                     -- 'scan_aps', 'nmap_scan', 'subghz_rx', etc.
    started_at TEXT NOT NULL,                 -- ISO 8601
    ended_at TEXT,
    raw_output TEXT,                          -- full tool response for provenance
    notes TEXT
);

-- Hosts: central entity — anything with an IP or MAC address
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,                                  -- IPv4 or IPv6 (nullable for MAC-only devices)
    mac TEXT,                                 -- normalized uppercase colon-separated
    hostname TEXT,
    os TEXT,                                  -- OS fingerprint
    vendor TEXT,                              -- OUI vendor lookup
    device_type TEXT,                         -- 'router', 'workstation', 'iot', 'mobile', 'unknown'
    tags TEXT,                                -- JSON array of user-applied tags
    first_seen TEXT NOT NULL,                 -- ISO 8601
    last_seen TEXT NOT NULL,
    scan_session_id INTEGER REFERENCES scan_sessions(id),
    notes TEXT,
    UNIQUE(ip, mac)                           -- dedupe on the IP+MAC pair
);

CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac);
CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen);

-- Ports: services discovered on hosts
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',     -- 'tcp', 'udp'
    state TEXT NOT NULL DEFAULT 'open',       -- 'open', 'closed', 'filtered'
    service TEXT,                             -- 'ssh', 'http', 'https', etc.
    banner TEXT,                              -- service banner / version string
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    scan_session_id INTEGER REFERENCES scan_sessions(id),
    UNIQUE(host_id, port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);

-- WiFi networks: access points discovered by Marauder / aircrack / bettercap
CREATE TABLE IF NOT EXISTS wifi_networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid TEXT NOT NULL,                      -- AP MAC address (normalized)
    ssid TEXT,                                -- can be NULL for hidden networks
    channel INTEGER,
    rssi INTEGER,                             -- signal strength (dBm, last observed)
    encryption TEXT,                          -- 'WPA2', 'WPA3', 'WEP', 'OPEN'
    wps INTEGER DEFAULT 0,                    -- 1 if WPS enabled
    host_id INTEGER REFERENCES hosts(id),     -- link to hosts if AP has an IP
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    scan_session_id INTEGER REFERENCES scan_sessions(id),
    notes TEXT,
    UNIQUE(bssid)
);

CREATE INDEX IF NOT EXISTS idx_wifi_bssid ON wifi_networks(bssid);

-- WiFi stations: client devices associated (or probing) to APs
CREATE TABLE IF NOT EXISTS wifi_stations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,                        -- station MAC (normalized)
    network_id INTEGER REFERENCES wifi_networks(id),  -- associated AP (nullable if probing)
    rssi INTEGER,
    probed_ssids TEXT,                        -- JSON array of SSIDs from probe requests
    host_id INTEGER REFERENCES hosts(id),     -- link to hosts table
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    scan_session_id INTEGER REFERENCES scan_sessions(id),
    UNIQUE(mac)
);

CREATE INDEX IF NOT EXISTS idx_wifi_stations_mac ON wifi_stations(mac);

-- RF signals: captures from PortaPack / Flipper SubGHz
CREATE TABLE IF NOT EXISTS rf_signals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    frequency_hz INTEGER NOT NULL,
    modulation TEXT,                          -- 'ASK/OOK', 'FSK', 'GFSK', 'AM', 'FM'
    protocol TEXT,                            -- 'SubGHz', 'ADS-B', 'POCSAG', 'TPMS', 'Weather', etc.
    data_hex TEXT,                            -- raw captured data (hex encoded)
    signal_strength INTEGER,                 -- dBm or RSSI
    source_device TEXT,                       -- 'portapack' or 'flipper'
    capture_file TEXT,                        -- path to .sub / .c16 / .wav file
    decoded_text TEXT,                        -- human-readable decode if available
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    scan_session_id INTEGER REFERENCES scan_sessions(id),
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_rf_freq ON rf_signals(frequency_hz);
CREATE INDEX IF NOT EXISTS idx_rf_protocol ON rf_signals(protocol);

-- BLE devices: discovered by Flipper / Marauder BLE scanning
CREATE TABLE IF NOT EXISTS ble_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,                        -- BLE address (may be random/rotating)
    name TEXT,                                -- advertised device name
    address_type TEXT DEFAULT 'public',       -- 'public', 'random', 'static'
    rssi INTEGER,
    services TEXT,                            -- JSON array of service UUIDs
    manufacturer_data TEXT,                   -- hex encoded manufacturer specific data
    host_id INTEGER REFERENCES hosts(id),
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    scan_session_id INTEGER REFERENCES scan_sessions(id),
    UNIQUE(mac)
);

CREATE INDEX IF NOT EXISTS idx_ble_mac ON ble_devices(mac);

-- RFID / NFC tags: read by Flipper Zero
CREATE TABLE IF NOT EXISTS rfid_nfc_tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag_type TEXT NOT NULL,                   -- 'nfc_a', 'nfc_b', 'em4100', 'hid_prox', 'indala', etc.
    uid TEXT NOT NULL,                        -- tag UID / serial (hex)
    protocol TEXT,                            -- 'ISO14443-A', 'ISO14443-B', 'EM-Marin', 'HID'
    atqa TEXT,                                -- NFC: ATQA bytes (hex)
    sak TEXT,                                 -- NFC: SAK byte (hex)
    data_hex TEXT,                            -- full dump if available
    label TEXT,                               -- user-assigned label ("Bob's badge")
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    scan_session_id INTEGER REFERENCES scan_sessions(id),
    notes TEXT,
    UNIQUE(tag_type, uid)
);

CREATE INDEX IF NOT EXISTS idx_rfid_uid ON rfid_nfc_tags(uid);

-- Credentials: harvested from any source
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,                            -- plaintext or hash
    hash_type TEXT,                           -- 'PMKID', 'WPA-PSK', 'NTLM', 'bcrypt', 'plaintext'
    cracked INTEGER DEFAULT 0,               -- 1 if hash was cracked
    source TEXT,                              -- 'pmkid_capture', 'evil_portal', 'brute_force', etc.
    host_id INTEGER REFERENCES hosts(id),
    wifi_network_id INTEGER REFERENCES wifi_networks(id),
    first_seen TEXT NOT NULL,
    scan_session_id INTEGER REFERENCES scan_sessions(id),
    notes TEXT
);
```

- [ ] **Step 2: Commit**

```bash
git add knowledge/target_schema.sql
git commit -m "feat(targets): add DDL for target intelligence tables"
```

---

### Task 2: Data Models — `knowledge/target_models.py`

**Files:**
- Create: `knowledge/target_models.py`

- [ ] **Step 1: Write the dataclasses**

```python
"""Data models for the protoPen target intelligence system."""

from dataclasses import dataclass, field


@dataclass
class ScanSession:
    id: int = 0
    engagement: str = ""
    tool: str = ""
    action: str = ""
    started_at: str = ""
    ended_at: str = ""
    raw_output: str = ""
    notes: str = ""


@dataclass
class Host:
    id: int = 0
    ip: str = ""
    mac: str = ""
    hostname: str = ""
    os: str = ""
    vendor: str = ""
    device_type: str = "unknown"
    tags: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    scan_session_id: int = 0
    notes: str = ""


@dataclass
class Port:
    id: int = 0
    host_id: int = 0
    port: int = 0
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    banner: str = ""
    first_seen: str = ""
    last_seen: str = ""
    scan_session_id: int = 0


@dataclass
class WifiNetwork:
    id: int = 0
    bssid: str = ""
    ssid: str = ""
    channel: int = 0
    rssi: int = 0
    encryption: str = ""
    wps: bool = False
    host_id: int = 0
    first_seen: str = ""
    last_seen: str = ""
    scan_session_id: int = 0
    notes: str = ""


@dataclass
class WifiStation:
    id: int = 0
    mac: str = ""
    network_id: int = 0
    rssi: int = 0
    probed_ssids: list[str] = field(default_factory=list)
    host_id: int = 0
    first_seen: str = ""
    last_seen: str = ""
    scan_session_id: int = 0


@dataclass
class RfSignal:
    id: int = 0
    frequency_hz: int = 0
    modulation: str = ""
    protocol: str = ""
    data_hex: str = ""
    signal_strength: int = 0
    source_device: str = ""
    capture_file: str = ""
    decoded_text: str = ""
    first_seen: str = ""
    last_seen: str = ""
    scan_session_id: int = 0
    notes: str = ""


@dataclass
class BleDevice:
    id: int = 0
    mac: str = ""
    name: str = ""
    address_type: str = "public"
    rssi: int = 0
    services: list[str] = field(default_factory=list)
    manufacturer_data: str = ""
    host_id: int = 0
    first_seen: str = ""
    last_seen: str = ""
    scan_session_id: int = 0


@dataclass
class RfidNfcTag:
    id: int = 0
    tag_type: str = ""
    uid: str = ""
    protocol: str = ""
    atqa: str = ""
    sak: str = ""
    data_hex: str = ""
    label: str = ""
    first_seen: str = ""
    last_seen: str = ""
    scan_session_id: int = 0
    notes: str = ""


@dataclass
class Credential:
    id: int = 0
    username: str = ""
    password: str = ""
    hash_type: str = ""
    cracked: bool = False
    source: str = ""
    host_id: int = 0
    wifi_network_id: int = 0
    first_seen: str = ""
    scan_session_id: int = 0
    notes: str = ""
```

- [ ] **Step 2: Commit**

```bash
git add knowledge/target_models.py
git commit -m "feat(targets): add dataclasses for target intelligence entities"
```

---

### Task 3: Target Store — `knowledge/target_store.py`

**Files:**
- Create: `knowledge/target_store.py`
- Test: `tests/test_target_store.py`

This is the largest task. The store follows the same singleton/lazy-init pattern as `KnowledgeStore`.

- [ ] **Step 1: Write failing tests**

```python
"""Tests for the TargetStore — CRUD, upsert, query, diff."""
import json
import pytest
from pathlib import Path

from knowledge.target_store import TargetStore


@pytest.fixture
def store(tmp_path):
    db_path = tmp_path / "targets.db"
    return TargetStore(db_path=str(db_path))


class TestScanSessions:
    def test_create_session(self, store):
        sid = store.create_scan_session(tool="nmap", action="nmap_scan")
        assert sid > 0

    def test_end_session(self, store):
        sid = store.create_scan_session(tool="marauder", action="scan_aps")
        store.end_scan_session(sid, raw_output="found 3 APs")
        session = store.get_scan_session(sid)
        assert session["ended_at"] is not None
        assert session["raw_output"] == "found 3 APs"


class TestHostUpsert:
    def test_insert_new_host(self, store):
        host_id = store.upsert_host(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:FF")
        assert host_id > 0

    def test_upsert_updates_last_seen(self, store):
        id1 = store.upsert_host(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:FF")
        id2 = store.upsert_host(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:FF", hostname="router")
        assert id1 == id2
        host = store.get_host(id1)
        assert host["hostname"] == "router"

    def test_mac_normalization(self, store):
        id1 = store.upsert_host(mac="aa:bb:cc:dd:ee:ff")
        id2 = store.upsert_host(mac="AA:BB:CC:DD:EE:FF")
        assert id1 == id2

    def test_query_hosts_by_subnet(self, store):
        store.upsert_host(ip="192.168.1.1")
        store.upsert_host(ip="192.168.1.50")
        store.upsert_host(ip="10.0.0.1")
        results = store.query_hosts(ip_prefix="192.168.1.")
        assert len(results) == 2


class TestPorts:
    def test_upsert_port(self, store):
        hid = store.upsert_host(ip="192.168.1.1")
        pid = store.upsert_port(host_id=hid, port=22, protocol="tcp", service="ssh")
        assert pid > 0

    def test_upsert_port_updates_service(self, store):
        hid = store.upsert_host(ip="192.168.1.1")
        pid1 = store.upsert_port(host_id=hid, port=80, protocol="tcp")
        pid2 = store.upsert_port(host_id=hid, port=80, protocol="tcp", service="nginx/1.25")
        assert pid1 == pid2
        ports = store.get_ports(hid)
        assert ports[0]["service"] == "nginx/1.25"


class TestWifiNetworks:
    def test_upsert_network(self, store):
        nid = store.upsert_wifi_network(bssid="AA:BB:CC:DD:EE:FF", ssid="TestNet", channel=6)
        assert nid > 0

    def test_upsert_dedupes_on_bssid(self, store):
        id1 = store.upsert_wifi_network(bssid="AA:BB:CC:DD:EE:FF", ssid="TestNet")
        id2 = store.upsert_wifi_network(bssid="AA:BB:CC:DD:EE:FF", rssi=-45)
        assert id1 == id2


class TestWifiStations:
    def test_upsert_station(self, store):
        sid = store.upsert_wifi_station(mac="11:22:33:44:55:66")
        assert sid > 0


class TestRfSignals:
    def test_add_signal(self, store):
        rid = store.add_rf_signal(frequency_hz=433920000, protocol="ASK/OOK", source_device="flipper")
        assert rid > 0


class TestBleDevices:
    def test_upsert_ble(self, store):
        bid = store.upsert_ble_device(mac="AA:BB:CC:DD:EE:FF", name="AirPods")
        assert bid > 0


class TestRfidNfcTags:
    def test_upsert_tag(self, store):
        tid = store.upsert_rfid_nfc_tag(tag_type="nfc_a", uid="04AABBCCDD")
        assert tid > 0

    def test_dedupes_on_type_uid(self, store):
        id1 = store.upsert_rfid_nfc_tag(tag_type="em4100", uid="AABBCCDDEE")
        id2 = store.upsert_rfid_nfc_tag(tag_type="em4100", uid="AABBCCDDEE", label="Bob's badge")
        assert id1 == id2


class TestCredentials:
    def test_add_credential(self, store):
        cid = store.add_credential(username="admin", password="hunter2", source="evil_portal")
        assert cid > 0


class TestStats:
    def test_stats_empty(self, store):
        stats = store.get_stats()
        assert stats["hosts"] == 0
        assert stats["wifi_networks"] == 0

    def test_stats_populated(self, store):
        store.upsert_host(ip="1.2.3.4")
        store.upsert_wifi_network(bssid="AA:BB:CC:DD:EE:FF")
        stats = store.get_stats()
        assert stats["hosts"] == 1
        assert stats["wifi_networks"] == 1


class TestDiffBaseline:
    def test_diff_shows_new_hosts(self, store):
        store.upsert_host(ip="192.168.1.1")
        # Simulate a baseline timestamp in the past
        diff = store.diff_since("2000-01-01T00:00:00Z")
        assert diff["new_hosts"] == 1

    def test_diff_shows_new_ports(self, store):
        hid = store.upsert_host(ip="192.168.1.1")
        store.upsert_port(host_id=hid, port=22)
        diff = store.diff_since("2000-01-01T00:00:00Z")
        assert diff["new_ports"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_target_store.py -v
```

Expected: `ModuleNotFoundError: No module named 'knowledge.target_store'`

- [ ] **Step 3: Write the TargetStore implementation**

Create `knowledge/target_store.py` with the following structure:

```python
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
        clean = ":".join(h[i:i+2] for i in range(0, 12, 2))
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
        self, tool: str, action: str, engagement: str = "", notes: str = "",
    ) -> int:
        db = self._get_db()
        cur = db.execute(
            "INSERT INTO scan_sessions (engagement, tool, action, started_at, notes) "
            "VALUES (?, ?, ?, ?, ?)",
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
                "SELECT id FROM hosts WHERE ip = ? AND mac = ?", (ip, mac),
            ).fetchone()
        elif ip:
            existing = db.execute(
                "SELECT id FROM hosts WHERE ip = ? AND (mac = '' OR mac IS NULL)", (ip,),
            ).fetchone()
        elif mac:
            existing = db.execute(
                "SELECT id FROM hosts WHERE mac = ? AND (ip = '' OR ip IS NULL)", (mac,),
            ).fetchone()

        if existing:
            # Update existing — merge non-empty fields
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
            if ip and not mac:
                # Fill in IP if we matched on MAC only
                pass
            if mac and not ip:
                pass
            params.append(host_id)
            db.execute(f"UPDATE hosts SET {', '.join(updates)} WHERE id = ?", params)
            db.commit()
            return host_id

        # Insert new
        cur = db.execute(
            "INSERT INTO hosts (ip, mac, hostname, os, vendor, device_type, tags, "
            "first_seen, last_seen, scan_session_id, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ip, mac, hostname, os, vendor, device_type,
             json.dumps(tags or []), now, now,
             scan_session_id or None, notes),
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
            (host_id, port, protocol, state, service, banner, now, now,
             scan_session_id or None),
        )
        db.commit()
        return cur.lastrowid

    def get_ports(self, host_id: int) -> list[dict]:
        db = self._get_db()
        rows = db.execute(
            "SELECT * FROM ports WHERE host_id = ? ORDER BY port", (host_id,),
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
            "SELECT id FROM wifi_networks WHERE bssid = ?", (bssid,),
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
            (bssid, ssid, channel, rssi, encryption, int(wps),
             host_id or None, now, now, scan_session_id or None, notes),
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
            "SELECT id FROM wifi_stations WHERE mac = ?", (mac,),
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
            (mac, network_id or None, rssi, json.dumps(probed_ssids or []),
             host_id or None, now, now, scan_session_id or None),
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
            (frequency_hz, modulation, protocol, data_hex, signal_strength,
             source_device, capture_file, decoded_text, now, now,
             scan_session_id or None, notes),
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
            "SELECT id FROM ble_devices WHERE mac = ?", (mac,),
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
            (mac, name, address_type, rssi, json.dumps(services or []),
             manufacturer_data, host_id or None, now, now, scan_session_id or None),
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
            (tag_type, uid, protocol, atqa, sak, data_hex, label,
             now, now, scan_session_id or None, notes),
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
            (username, password, hash_type, int(cracked), source,
             host_id or None, wifi_network_id or None, now,
             scan_session_id or None, notes),
        )
        db.commit()
        return cur.lastrowid

    # ── Stats & Diff ───────────────────────────────────────────────

    def get_stats(self) -> dict:
        db = self._get_db()
        tables = [
            "hosts", "ports", "wifi_networks", "wifi_stations",
            "rf_signals", "ble_devices", "rfid_nfc_tags", "credentials", "scan_sessions",
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
            ("hosts", "first_seen"), ("ports", "first_seen"),
            ("wifi_networks", "first_seen"), ("wifi_stations", "first_seen"),
            ("rf_signals", "first_seen"), ("ble_devices", "first_seen"),
            ("rfid_nfc_tags", "first_seen"), ("credentials", "first_seen"),
        ]:
            row = db.execute(
                f"SELECT COUNT(*) as cnt FROM {table} WHERE {col} >= ?", (since,),
            ).fetchone()
            diff[f"new_{table}"] = row["cnt"]
        return diff

    def close(self):
        if self._db:
            self._db.close()
            self._db = None
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_target_store.py -v
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add knowledge/target_store.py tests/test_target_store.py
git commit -m "feat(targets): add TargetStore with CRUD, upsert, query, diff"
```

---

### Task 4: Agent Tool — `tools/target_intel.py`

**Files:**
- Create: `tools/target_intel.py`
- Test: `tests/test_target_intel.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for the TargetIntelTool agent wrapper."""
import pytest
import asyncio

from knowledge.target_store import TargetStore
from tools.target_intel import TargetIntelTool


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


@pytest.fixture
def tool(store):
    return TargetIntelTool(store)


class TestToolInterface:
    def test_name(self, tool):
        assert tool.name == "target_intel"

    def test_parameters_has_action(self, tool):
        assert "action" in tool.parameters["properties"]

    def test_unknown_action(self, tool):
        result = asyncio.get_event_loop().run_until_complete(
            tool.execute(action="bogus")
        )
        assert "Unknown action" in result


class TestUpsertHost:
    def test_upsert_via_tool(self, tool):
        result = asyncio.get_event_loop().run_until_complete(
            tool.execute(action="upsert_host", ip="10.0.0.1", hostname="gateway")
        )
        assert "id" in result.lower() or "10.0.0.1" in result


class TestQueryHosts:
    def test_query_empty(self, tool):
        result = asyncio.get_event_loop().run_until_complete(
            tool.execute(action="query_hosts")
        )
        assert "0 host" in result.lower() or "no host" in result.lower()


class TestStats:
    def test_stats(self, tool):
        result = asyncio.get_event_loop().run_until_complete(
            tool.execute(action="stats")
        )
        assert "hosts" in result.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_target_intel.py -v
```

- [ ] **Step 3: Write the tool**

```python
"""Target intelligence agent tool.

Wraps TargetStore as a nanobot/LangGraph-compatible Tool for the agent
to query, upsert, and analyze target data across all sensor domains.
"""
from __future__ import annotations

import json
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
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_target_intel.py -v
```

- [ ] **Step 5: Commit**

```bash
git add tools/target_intel.py tests/test_target_intel.py
git commit -m "feat(targets): add TargetIntelTool agent wrapper"
```

---

### Task 5: Engagement Auto-Upsert

**Files:**
- Modify: `tools/engagement.py:141-155` (the `log_finding` method)
- Test: `tests/test_engagement_autoupsert.py`

When `log_finding` is called and the finding detail contains an IP or MAC address, auto-upsert a host into the TargetStore.

- [ ] **Step 1: Write failing test**

```python
"""Tests for engagement → target_store auto-upsert integration."""
import json
import pytest
from pathlib import Path

from tools.engagement import EngagementManager
from knowledge.target_store import TargetStore


@pytest.fixture
def config():
    with open("config/engagement-config.json") as f:
        return json.load(f)


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


@pytest.fixture
def mgr(config, tmp_path, store):
    config["engagement"]["workspace_dir"] = str(tmp_path)
    mgr = EngagementManager(config)
    mgr.target_store = store
    return mgr


class TestAutoUpsert:
    def test_finding_with_ip_creates_host(self, mgr, store):
        mgr.start("test-engagement", scope="192.168.1.0/24")
        mgr.log_finding(
            severity="high", category="open-port",
            title="SSH on 192.168.1.1",
            detail="Port 22 open on 192.168.1.1 running OpenSSH 9.0",
        )
        hosts = store.query_hosts(ip_prefix="192.168.1.1")
        assert len(hosts) == 1

    def test_finding_without_ip_no_crash(self, mgr, store):
        mgr.start("test-engagement")
        mgr.log_finding(
            severity="info", category="general",
            title="Observation", detail="Nothing to upsert here",
        )
        assert store.get_stats()["hosts"] == 0

    def test_finding_with_mac_creates_host(self, mgr, store):
        mgr.start("test-engagement")
        mgr.log_finding(
            severity="medium", category="wifi",
            title="Rogue AP",
            detail="Detected rogue AP with BSSID AA:BB:CC:DD:EE:FF",
        )
        hosts = store.query_hosts()
        assert len(hosts) >= 1
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_engagement_autoupsert.py -v
```

- [ ] **Step 3: Modify `tools/engagement.py`**

Add an `import re` at the top. Add a `target_store` attribute (default `None`). Modify `log_finding` to extract IPs and MACs from the detail text and auto-upsert:

At the top of the file, add:
```python
import re
```

Add to `__init__` after `self.findings = []`:
```python
self.target_store = None  # Injected TargetStore for auto-upsert
```

Add a helper method after `log_finding`:
```python
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_MAC_RE = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b')

def _auto_upsert_targets(self, detail: str):
    """Extract IPs and MACs from finding detail and upsert into target store."""
    if self.target_store is None:
        return
    try:
        ips = self._IP_RE.findall(detail)
        macs = self._MAC_RE.findall(detail)
        for ip in ips:
            self.target_store.upsert_host(ip=ip)
        for mac in macs:
            if mac not in [ip for ip in ips]:  # don't confuse MAC for IP
                self.target_store.upsert_host(mac=mac)
    except Exception as exc:
        logger.warning("Auto-upsert failed: %s", exc)
```

Add a call to `_auto_upsert_targets(detail)` at the end of `log_finding`, after the `_send_alert` block.

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_engagement_autoupsert.py tests/test_engagement.py -v
```

Expected: all pass (existing engagement tests still green + new auto-upsert tests pass).

- [ ] **Step 5: Commit**

```bash
git add tools/engagement.py tests/test_engagement_autoupsert.py
git commit -m "feat(targets): auto-upsert hosts from engagement findings"
```

---

### Task 6: Wire into Server

**Files:**
- Modify: `server.py` (~lines 307-315, and tool registration)

- [ ] **Step 1: Add TargetStore singleton**

Near the existing `_knowledge_store` singleton (around line 307), add:

```python
_target_store = None

def _get_target_store():
    global _target_store
    if _target_store is None:
        from knowledge.target_store import TargetStore
        _target_store = TargetStore()
    return _target_store
```

- [ ] **Step 2: Inject into tool registration**

Find where tools are assembled (in `_init_langgraph_agent` or equivalent) and add:

```python
from tools.target_intel import TargetIntelTool
target_store = _get_target_store()
target_tool = TargetIntelTool(target_store)
```

Add `target_tool` to the tools list passed to the agent.

- [ ] **Step 3: Inject TargetStore into EngagementManager**

Where `EngagementManager` is instantiated, add:
```python
engagement_mgr.target_store = _get_target_store()
```

- [ ] **Step 4: Verify server starts**

```bash
python -c "from knowledge.target_store import TargetStore; s = TargetStore('/tmp/test_targets.db'); print(s.get_stats())"
```

- [ ] **Step 5: Commit**

```bash
git add server.py
git commit -m "feat(targets): wire TargetStore and TargetIntelTool into server"
```

---

### Task 7: Full Test Suite Verification

- [ ] **Step 1: Run entire test suite**

```bash
pytest tests/ -v
```

Expected: all tests pass, zero regressions.

- [ ] **Step 2: Commit any fixes if needed**

```bash
git add -A && git commit -m "fix: address test regressions from target intelligence integration"
```
