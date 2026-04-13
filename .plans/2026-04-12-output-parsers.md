# Output Parser Middleware Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auto-ingest discovered entities (hosts, ports, WiFi APs, stations, RF signals, NFC/RFID tags) into `TargetStore` whenever a pentest tool returns discovery output, with zero agent overhead.

**Architecture:** A `tools/parsers/` package contains one parser module per output format. Each parser is a pure function `parse(raw: str, store: TargetStore) -> list[dict]` that extracts entities and upserts them. A central dispatcher `ingest_output(tool_name, action, raw, store)` looks up the right parser and calls it, swallowing errors so a broken parser never breaks a tool. Each tool's `execute()` gets a 3-line post-hook to call the dispatcher.

**Tech Stack:** Python 3.11, `xml.etree.ElementTree` (nmap), regex (everything else), `pytest` with `tmp_path` fixtures.

---

### Task 1: Parser package scaffold + dispatcher

**Files:**

- Create: `tools/parsers/__init__.py`
- Test: `tests/test_parsers_dispatch.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_parsers_dispatch.py
"""Tests for the parser dispatch layer."""
import pytest
from unittest.mock import MagicMock
from knowledge.target_store import TargetStore
from tools.parsers import ingest_output


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


class TestDispatcher:
    def test_known_parser_is_called(self, store):
        """nmap_scan should trigger the nmap parser and return entities."""
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        entities = ingest_output("blackarch", "nmap_scan", xml, store)
        assert len(entities) > 0

    def test_unknown_action_returns_empty(self, store):
        """Unknown tool+action combos silently return empty list."""
        result = ingest_output("blackarch", "does_not_exist", "whatever", store)
        assert result == []

    def test_parser_error_returns_empty(self, store, monkeypatch):
        """A parser that raises should be caught; returns empty list."""
        def bad_parser(raw, s):
            raise ValueError("boom")
        from tools.parsers import PARSER_MAP
        monkeypatch.setitem(PARSER_MAP, ("blackarch", "nmap_scan"), bad_parser)
        result = ingest_output("blackarch", "nmap_scan", "<bad/>", store)
        assert result == []

    def test_none_store_returns_empty(self):
        """If store is None, skip parsing entirely."""
        result = ingest_output("blackarch", "nmap_scan", "<x/>", None)
        assert result == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_parsers_dispatch.py -v`
Expected: ImportError — `tools.parsers` does not exist

- [ ] **Step 3: Write the dispatcher**

```python
# tools/parsers/__init__.py
"""Output parser registry and dispatcher.

Each parser: parse(raw: str, store: TargetStore) -> list[dict]
Parsers are registered in PARSER_MAP keyed by (tool_name, action).
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

logger = logging.getLogger(__name__)

# Populated by parser module imports below
PARSER_MAP: dict[tuple[str, str], callable] = {}


def ingest_output(
    tool_name: str,
    action: str,
    raw: str,
    store: "TargetStore | None",
) -> list[dict]:
    """Route tool output through the matching parser; return ingested entities.

    Never raises — parser errors are logged and swallowed.
    """
    if store is None:
        return []
    parser = PARSER_MAP.get((tool_name, action))
    if parser is None:
        return []
    try:
        return parser(raw, store)
    except Exception:
        logger.exception("Parser failed for %s/%s", tool_name, action)
        return []


# ---- register parsers (imports trigger registration) ----
from tools.parsers import nmap_xml      # noqa: E402,F401
from tools.parsers import bettercap     # noqa: E402,F401
from tools.parsers import marauder_wifi # noqa: E402,F401
from tools.parsers import flipper_rf    # noqa: E402,F401
```

- [ ] **Step 4: Create empty parser stubs so imports don't fail**

Create four stub files that each register themselves in `PARSER_MAP`:

```python
# tools/parsers/nmap_xml.py
"""Parser for nmap -oX - XML output."""
from tools.parsers import PARSER_MAP

def parse(raw, store):
    return []

PARSER_MAP[("blackarch", "nmap_scan")] = parse
PARSER_MAP[("blackarch", "nmap_vuln_scan")] = parse
```

```python
# tools/parsers/bettercap.py
"""Parser for bettercap net.show ASCII table output."""
from tools.parsers import PARSER_MAP

def parse(raw, store):
    return []

PARSER_MAP[("blackarch", "bettercap_recon")] = parse
```

```python
# tools/parsers/marauder_wifi.py
"""Parser for ESP32 Marauder scan_aps / scan_stations output."""
from tools.parsers import PARSER_MAP

def parse_aps(raw, store):
    return []

def parse_stations(raw, store):
    return []

PARSER_MAP[("marauder", "scan_aps")] = parse_aps
PARSER_MAP[("marauder", "scan_stations")] = parse_stations
```

```python
# tools/parsers/flipper_rf.py
"""Parser for Flipper Zero nfc/rfid/subghz output."""
from tools.parsers import PARSER_MAP

def parse_nfc(raw, store):
    return []

def parse_rfid(raw, store):
    return []

def parse_subghz(raw, store):
    return []

PARSER_MAP[("flipper", "nfc_detect")] = parse_nfc
PARSER_MAP[("flipper", "rfid_read")] = parse_rfid
PARSER_MAP[("flipper", "subghz_rx")] = parse_subghz
```

- [ ] **Step 5: Run tests to verify dispatch passes**

Run: `pytest tests/test_parsers_dispatch.py -v`
Expected: All 4 tests PASS

- [ ] **Step 6: Commit**

```bash
git add tools/parsers/ tests/test_parsers_dispatch.py
git commit -m "feat(parsers): add dispatch registry with stubs for all parser modules"
```

---

### Task 2: Nmap XML parser

**Files:**

- Modify: `tools/parsers/nmap_xml.py`
- Test: `tests/test_parser_nmap.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_parser_nmap.py
"""Tests for nmap XML output parser."""
import pytest
from knowledge.target_store import TargetStore
from tools.parsers.nmap_xml import parse


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


NMAP_SINGLE_HOST = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - 192.168.1.1">
  <host starttime="1712900000" endtime="1712900010">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme Corp"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.22"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.15" accuracy="95"/></os>
  </host>
</nmaprun>"""

NMAP_MULTI_HOST = """<?xml version="1.0"?>
<nmaprun>
  <host><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/>
      <service name="https"/></port></ports></host>
  <host><address addr="10.0.0.2" addrtype="ipv4"/>
    <ports><port protocol="udp" portid="53"><state state="open"/>
      <service name="dns"/></port></ports></host>
</nmaprun>"""

NMAP_NO_HOSTS = """<?xml version="1.0"?><nmaprun></nmaprun>"""

NMAP_GARBAGE = """not xml at all {{{"""


class TestNmapParser:
    def test_single_host_with_ports(self, store):
        entities = parse(NMAP_SINGLE_HOST, store)
        hosts = [e for e in entities if e["type"] == "host"]
        ports = [e for e in entities if e["type"] == "port"]
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "192.168.1.1"
        assert hosts[0]["mac"] == "AA:BB:CC:DD:EE:FF"
        assert hosts[0]["hostname"] == "router.local"
        assert hosts[0]["vendor"] == "Acme Corp"
        assert len(ports) == 2
        assert any(p["port"] == 22 and p["service"] == "ssh" for p in ports)
        assert any(p["port"] == 80 and p["service"] == "http" for p in ports)

    def test_os_detection(self, store):
        entities = parse(NMAP_SINGLE_HOST, store)
        hosts = [e for e in entities if e["type"] == "host"]
        assert hosts[0]["os"] == "Linux 5.15"

    def test_multi_host(self, store):
        entities = parse(NMAP_MULTI_HOST, store)
        hosts = [e for e in entities if e["type"] == "host"]
        assert len(hosts) == 2
        ips = {h["ip"] for h in hosts}
        assert ips == {"10.0.0.1", "10.0.0.2"}

    def test_host_persisted_to_store(self, store):
        parse(NMAP_SINGLE_HOST, store)
        rows = store.query_hosts(ip_prefix="192.168.1.")
        assert len(rows) == 1
        assert rows[0]["hostname"] == "router.local"

    def test_ports_persisted_to_store(self, store):
        parse(NMAP_SINGLE_HOST, store)
        hosts = store.query_hosts(ip_prefix="192.168.1.")
        ports = store.get_ports(hosts[0]["id"])
        assert len(ports) == 2

    def test_empty_nmaprun(self, store):
        entities = parse(NMAP_NO_HOSTS, store)
        assert entities == []

    def test_garbage_input(self, store):
        entities = parse(NMAP_GARBAGE, store)
        assert entities == []

    def test_idempotent_upsert(self, store):
        parse(NMAP_SINGLE_HOST, store)
        parse(NMAP_SINGLE_HOST, store)
        rows = store.query_hosts(ip_prefix="192.168.1.")
        assert len(rows) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_parser_nmap.py -v`
Expected: FAIL — `parse` returns `[]`

- [ ] **Step 3: Implement nmap_xml parser**

```python
# tools/parsers/nmap_xml.py
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
            ip=ip, mac=mac, hostname=hostname,
            os=os_match, vendor=vendor,
        )
        entities.append({
            "type": "host", "id": host_id,
            "ip": ip, "mac": mac, "hostname": hostname,
            "os": os_match, "vendor": vendor,
        })

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
                host_id=host_id, port=portid, protocol=protocol,
                state=state, service=service, banner=banner,
            )
            entities.append({
                "type": "port", "id": port_row_id,
                "host_id": host_id, "port": portid,
                "protocol": protocol, "service": service,
                "banner": banner,
            })

    return entities


PARSER_MAP[("blackarch", "nmap_scan")] = parse
PARSER_MAP[("blackarch", "nmap_vuln_scan")] = parse
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_parser_nmap.py -v`
Expected: All 8 PASS

- [ ] **Step 5: Commit**

```bash
git add tools/parsers/nmap_xml.py tests/test_parser_nmap.py
git commit -m "feat(parsers): nmap XML parser — hosts, ports, OS, MAC/vendor"
```

---

### Task 3: Bettercap net.show parser

**Files:**

- Modify: `tools/parsers/bettercap.py`
- Test: `tests/test_parser_bettercap.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_parser_bettercap.py
"""Tests for bettercap net.show ASCII table parser."""
import pytest
from knowledge.target_store import TargetStore
from tools.parsers.bettercap import parse


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


BETTERCAP_TABLE = """\
192.168.1.0/24 > 192.168.1.100  » net.recon
┌───────────────┬───────────────────┬──────────────────┬────────────────┬──────┬───────┐
│    IP Address │ MAC Address       │ Hostname         │ Vendor         │ Sent │ Recvd │
├───────────────┼───────────────────┼──────────────────┼────────────────┼──────┼───────┤
│ 192.168.1.1   │ AA:BB:CC:DD:EE:01 │ gateway.local    │ Netgear Inc    │  12k │   34k │
│ 192.168.1.42  │ 11:22:33:44:55:66 │ kali             │ Intel Corp     │ 102k │  201k │
│ 192.168.1.100 │ DE:AD:BE:EF:CA:FE │                  │ Raspberry Pi   │   1k │    2k │
└───────────────┴───────────────────┴──────────────────┴────────────────┴──────┴───────┘
"""

BETTERCAP_EMPTY = """\
192.168.1.0/24 > 192.168.1.100  » net.recon
No hosts detected.
"""

BETTERCAP_GARBAGE = "something unrelated"


class TestBettercapParser:
    def test_parses_three_hosts(self, store):
        entities = parse(BETTERCAP_TABLE, store)
        assert len(entities) == 3

    def test_ip_and_mac_extracted(self, store):
        entities = parse(BETTERCAP_TABLE, store)
        gateway = next(e for e in entities if e["ip"] == "192.168.1.1")
        assert gateway["mac"] == "AA:BB:CC:DD:EE:01"
        assert gateway["hostname"] == "gateway.local"
        assert gateway["vendor"] == "Netgear Inc"

    def test_empty_hostname(self, store):
        entities = parse(BETTERCAP_TABLE, store)
        rpi = next(e for e in entities if e["ip"] == "192.168.1.100")
        assert rpi["hostname"] == ""

    def test_hosts_persisted(self, store):
        parse(BETTERCAP_TABLE, store)
        rows = store.query_hosts(ip_prefix="192.168.1.")
        assert len(rows) == 3

    def test_empty_table(self, store):
        assert parse(BETTERCAP_EMPTY, store) == []

    def test_garbage_input(self, store):
        assert parse(BETTERCAP_GARBAGE, store) == []

    def test_idempotent(self, store):
        parse(BETTERCAP_TABLE, store)
        parse(BETTERCAP_TABLE, store)
        assert len(store.query_hosts(ip_prefix="192.168.1.")) == 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_parser_bettercap.py -v`
Expected: FAIL — `parse` returns `[]`

- [ ] **Step 3: Implement bettercap parser**

```python
# tools/parsers/bettercap.py
"""Parser for bettercap net.show ASCII table → hosts into TargetStore."""
from __future__ import annotations

import re
import logging
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

logger = logging.getLogger(__name__)

# Matches table rows with │-delimited columns:
#   │ IP │ MAC │ Hostname │ Vendor │ Sent │ Recvd │
_ROW_RE = re.compile(
    r"│\s*(\d{1,3}(?:\.\d{1,3}){3})\s*│\s*"
    r"([0-9A-Fa-f:]{17})\s*│\s*"
    r"(.*?)\s*│\s*"
    r"(.*?)\s*│\s*"
    r".*?│\s*.*?│"
)


def parse(raw: str, store: TargetStore) -> list[dict]:
    """Parse bettercap net.show table, upsert hosts, return entity list."""
    entities: list[dict] = []
    for m in _ROW_RE.finditer(raw):
        ip = m.group(1)
        mac = m.group(2).upper()
        hostname = m.group(3).strip()
        vendor = m.group(4).strip()

        host_id = store.upsert_host(
            ip=ip, mac=mac, hostname=hostname, vendor=vendor,
        )
        entities.append({
            "type": "host", "id": host_id,
            "ip": ip, "mac": mac,
            "hostname": hostname, "vendor": vendor,
        })
    return entities


PARSER_MAP[("blackarch", "bettercap_recon")] = parse
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_parser_bettercap.py -v`
Expected: All 7 PASS

- [ ] **Step 5: Commit**

```bash
git add tools/parsers/bettercap.py tests/test_parser_bettercap.py
git commit -m "feat(parsers): bettercap net.show table parser — hosts"
```

---

### Task 4: Marauder WiFi parser (scan_aps + scan_stations)

**Files:**

- Modify: `tools/parsers/marauder_wifi.py`
- Test: `tests/test_parser_marauder.py`

- [ ] **Step 1: Write failing tests**

The ESP32 Marauder firmware outputs scan results in a characteristic format. AP scans print one line per AP, station scans print one line per client. The exact format varies by firmware version but follows a consistent pattern.

```python
# tests/test_parser_marauder.py
"""Tests for Marauder WiFi scan output parsers."""
import pytest
from knowledge.target_store import TargetStore
from tools.parsers.marauder_wifi import parse_aps, parse_stations


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


SCAN_APS_OUTPUT = """\
[*] Scanning for APs...
[*] Scan complete. 3 APs found:
 SSID: HomeNet, BSSID: AA:BB:CC:DD:EE:01, CH: 6, RSSI: -42, ENC: WPA2
 SSID: CoffeeShop, BSSID: AA:BB:CC:DD:EE:02, CH: 11, RSSI: -65, ENC: OPEN
 SSID: , BSSID: AA:BB:CC:DD:EE:03, CH: 1, RSSI: -80, ENC: WPA3
"""

SCAN_STATIONS_OUTPUT = """\
[*] Scanning for stations...
[*] Scan complete. 2 stations found:
 STA: 11:22:33:44:55:01, AP: AA:BB:CC:DD:EE:01, RSSI: -38
 STA: 11:22:33:44:55:02, AP: AA:BB:CC:DD:EE:02, RSSI: -71
"""


class TestMarauderAPs:
    def test_parses_three_aps(self, store):
        entities = parse_aps(SCAN_APS_OUTPUT, store)
        assert len(entities) == 3

    def test_ap_fields(self, store):
        entities = parse_aps(SCAN_APS_OUTPUT, store)
        home = next(e for e in entities if e["ssid"] == "HomeNet")
        assert home["bssid"] == "AA:BB:CC:DD:EE:01"
        assert home["channel"] == 6
        assert home["rssi"] == -42
        assert home["encryption"] == "WPA2"

    def test_hidden_ssid(self, store):
        entities = parse_aps(SCAN_APS_OUTPUT, store)
        hidden = next(e for e in entities if e["bssid"] == "AA:BB:CC:DD:EE:03")
        assert hidden["ssid"] == ""

    def test_persisted_to_store(self, store):
        parse_aps(SCAN_APS_OUTPUT, store)
        stats = store.get_stats()
        assert stats["wifi_networks"] == 3

    def test_empty_output(self, store):
        assert parse_aps("", store) == []

    def test_no_aps_found(self, store):
        assert parse_aps("[*] Scan complete. 0 APs found:", store) == []

    def test_idempotent(self, store):
        parse_aps(SCAN_APS_OUTPUT, store)
        parse_aps(SCAN_APS_OUTPUT, store)
        assert store.get_stats()["wifi_networks"] == 3


class TestMarauderStations:
    def test_parses_two_stations(self, store):
        entities = parse_stations(SCAN_STATIONS_OUTPUT, store)
        assert len(entities) == 2

    def test_station_fields(self, store):
        entities = parse_stations(SCAN_STATIONS_OUTPUT, store)
        s = next(e for e in entities if e["mac"] == "11:22:33:44:55:01")
        assert s["rssi"] == -38

    def test_persisted_to_store(self, store):
        parse_stations(SCAN_STATIONS_OUTPUT, store)
        stats = store.get_stats()
        assert stats["wifi_stations"] == 2

    def test_empty_output(self, store):
        assert parse_stations("", store) == []

    def test_idempotent(self, store):
        parse_stations(SCAN_STATIONS_OUTPUT, store)
        parse_stations(SCAN_STATIONS_OUTPUT, store)
        assert store.get_stats()["wifi_stations"] == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_parser_marauder.py -v`
Expected: FAIL — parsers return `[]`

- [ ] **Step 3: Implement marauder WiFi parsers**

```python
# tools/parsers/marauder_wifi.py
"""Parser for ESP32 Marauder scan_aps / scan_stations serial output."""
from __future__ import annotations

import re
import logging
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

logger = logging.getLogger(__name__)

# AP line: " SSID: HomeNet, BSSID: AA:BB:CC:DD:EE:01, CH: 6, RSSI: -42, ENC: WPA2"
_AP_RE = re.compile(
    r"SSID:\s*(.*?),\s*BSSID:\s*([0-9A-Fa-f:]{17}),\s*"
    r"CH:\s*(\d+),\s*RSSI:\s*(-?\d+),\s*ENC:\s*(\S+)"
)

# Station line: " STA: 11:22:33:44:55:01, AP: AA:BB:CC:DD:EE:01, RSSI: -38"
_STA_RE = re.compile(
    r"STA:\s*([0-9A-Fa-f:]{17}),\s*AP:\s*([0-9A-Fa-f:]{17}),\s*"
    r"RSSI:\s*(-?\d+)"
)


def parse_aps(raw: str, store: TargetStore) -> list[dict]:
    """Parse Marauder scanap output, upsert WiFi networks."""
    entities: list[dict] = []
    for m in _AP_RE.finditer(raw):
        ssid = m.group(1).strip()
        bssid = m.group(2).upper()
        channel = int(m.group(3))
        rssi = int(m.group(4))
        encryption = m.group(5)

        net_id = store.upsert_wifi_network(
            bssid=bssid, ssid=ssid, channel=channel,
            rssi=rssi, encryption=encryption,
        )
        entities.append({
            "type": "wifi_network", "id": net_id,
            "bssid": bssid, "ssid": ssid,
            "channel": channel, "rssi": rssi,
            "encryption": encryption,
        })
    return entities


def parse_stations(raw: str, store: TargetStore) -> list[dict]:
    """Parse Marauder scansta output, upsert WiFi stations."""
    entities: list[dict] = []
    for m in _STA_RE.finditer(raw):
        mac = m.group(1).upper()
        rssi = int(m.group(3))
        # Note: AP BSSID is captured but WiFi station upsert uses network_id
        # (int FK). We'd need to look up the network by BSSID to link them.
        # For now, store the station without the FK link — the data is still
        # captured and can be correlated later via the WiFi networks table.
        sta_id = store.upsert_wifi_station(mac=mac, rssi=rssi)
        entities.append({
            "type": "wifi_station", "id": sta_id,
            "mac": mac, "rssi": rssi,
        })
    return entities


PARSER_MAP[("marauder", "scan_aps")] = parse_aps
PARSER_MAP[("marauder", "scan_stations")] = parse_stations
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_parser_marauder.py -v`
Expected: All 12 PASS

- [ ] **Step 5: Commit**

```bash
git add tools/parsers/marauder_wifi.py tests/test_parser_marauder.py
git commit -m "feat(parsers): marauder scan_aps + scan_stations parsers"
```

---

### Task 5: Flipper RF parser (nfc_detect, rfid_read, subghz_rx)

**Files:**

- Modify: `tools/parsers/flipper_rf.py`
- Test: `tests/test_parser_flipper.py`

- [ ] **Step 1: Write failing tests**

Flipper Zero CLI output follows a key-value format. These fixtures are based on real Flipper CLI serial responses.

```python
# tests/test_parser_flipper.py
"""Tests for Flipper Zero NFC/RFID/SubGHz output parsers."""
import pytest
from knowledge.target_store import TargetStore
from tools.parsers.flipper_rf import parse_nfc, parse_rfid, parse_subghz


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


NFC_DETECT_OUTPUT = """\
NFC card detected
Type: NTAG215
UID: 04:A3:2B:1C:7E:6D:80
ATQA: 44:00
SAK: 00
"""

NFC_NO_CARD = "NFC card not detected"

RFID_READ_OUTPUT = """\
Protocol: EM4100
Data: 01 23 45 67 89
"""

RFID_NO_TAG = "No RFID tag detected"

SUBGHZ_RX_OUTPUT = """\
Protocol: Princeton
Bit: 24
Key: 0x 00 AA BB
TE: 400
Freq: 433920000 Hz
"""

SUBGHZ_RX_MULTI = """\
Protocol: Princeton
Bit: 24
Key: 0x 00 AA BB
TE: 400
Freq: 433920000 Hz

Protocol: CAME
Bit: 12
Key: 0x AB C
TE: 320
Freq: 433920000 Hz
"""


class TestFlipperNfc:
    def test_parses_nfc_tag(self, store):
        entities = parse_nfc(NFC_DETECT_OUTPUT, store)
        assert len(entities) == 1
        assert entities[0]["tag_type"] == "NTAG215"
        assert entities[0]["uid"] == "04:A3:2B:1C:7E:6D:80"

    def test_atqa_sak_captured(self, store):
        entities = parse_nfc(NFC_DETECT_OUTPUT, store)
        assert entities[0]["atqa"] == "44:00"
        assert entities[0]["sak"] == "00"

    def test_persisted_to_store(self, store):
        parse_nfc(NFC_DETECT_OUTPUT, store)
        assert store.get_stats()["rfid_nfc_tags"] == 1

    def test_no_card(self, store):
        assert parse_nfc(NFC_NO_CARD, store) == []

    def test_empty(self, store):
        assert parse_nfc("", store) == []

    def test_idempotent(self, store):
        parse_nfc(NFC_DETECT_OUTPUT, store)
        parse_nfc(NFC_DETECT_OUTPUT, store)
        assert store.get_stats()["rfid_nfc_tags"] == 1


class TestFlipperRfid:
    def test_parses_rfid_tag(self, store):
        entities = parse_rfid(RFID_READ_OUTPUT, store)
        assert len(entities) == 1
        assert entities[0]["tag_type"] == "EM4100"
        assert entities[0]["data_hex"] == "01 23 45 67 89"

    def test_persisted_to_store(self, store):
        parse_rfid(RFID_READ_OUTPUT, store)
        assert store.get_stats()["rfid_nfc_tags"] == 1

    def test_no_tag(self, store):
        assert parse_rfid(RFID_NO_TAG, store) == []

    def test_empty(self, store):
        assert parse_rfid("", store) == []


class TestFlipperSubGhz:
    def test_parses_signal(self, store):
        entities = parse_subghz(SUBGHZ_RX_OUTPUT, store)
        assert len(entities) == 1
        assert entities[0]["protocol"] == "Princeton"
        assert entities[0]["frequency_hz"] == 433920000
        assert entities[0]["data_hex"] == "00 AA BB"

    def test_multi_signal(self, store):
        entities = parse_subghz(SUBGHZ_RX_MULTI, store)
        assert len(entities) == 2
        protos = {e["protocol"] for e in entities}
        assert protos == {"Princeton", "CAME"}

    def test_persisted_to_store(self, store):
        parse_subghz(SUBGHZ_RX_OUTPUT, store)
        assert store.get_stats()["rf_signals"] == 1

    def test_empty(self, store):
        assert parse_subghz("", store) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_parser_flipper.py -v`
Expected: FAIL — parsers return `[]`

- [ ] **Step 3: Implement flipper RF parsers**

```python
# tools/parsers/flipper_rf.py
"""Parsers for Flipper Zero NFC, RFID, and Sub-GHz serial output."""
from __future__ import annotations

import re
import logging
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

logger = logging.getLogger(__name__)

# ---- NFC detect ----
_NFC_TYPE_RE = re.compile(r"Type:\s*(.+)")
_NFC_UID_RE = re.compile(r"UID:\s*([0-9A-Fa-f:]+)")
_NFC_ATQA_RE = re.compile(r"ATQA:\s*([0-9A-Fa-f:]+)")
_NFC_SAK_RE = re.compile(r"SAK:\s*([0-9A-Fa-f]+)")


def parse_nfc(raw: str, store: TargetStore) -> list[dict]:
    """Parse Flipper nfc detect output, upsert RFID/NFC tags."""
    uid_m = _NFC_UID_RE.search(raw)
    type_m = _NFC_TYPE_RE.search(raw)
    if not uid_m or not type_m:
        return []

    uid = uid_m.group(1).strip()
    tag_type = type_m.group(1).strip()
    atqa_m = _NFC_ATQA_RE.search(raw)
    sak_m = _NFC_SAK_RE.search(raw)
    atqa = atqa_m.group(1).strip() if atqa_m else ""
    sak = sak_m.group(1).strip() if sak_m else ""

    tag_id = store.upsert_rfid_nfc_tag(
        tag_type=tag_type, uid=uid, protocol="NFC",
        atqa=atqa, sak=sak,
    )
    return [{
        "type": "rfid_nfc_tag", "id": tag_id,
        "tag_type": tag_type, "uid": uid,
        "atqa": atqa, "sak": sak,
    }]


# ---- RFID read ----
_RFID_PROTO_RE = re.compile(r"Protocol:\s*(.+)")
_RFID_DATA_RE = re.compile(r"Data:\s*([0-9A-Fa-f ]+)")


def parse_rfid(raw: str, store: TargetStore) -> list[dict]:
    """Parse Flipper rfid read output, upsert RFID/NFC tags."""
    proto_m = _RFID_PROTO_RE.search(raw)
    data_m = _RFID_DATA_RE.search(raw)
    if not proto_m or not data_m:
        return []

    protocol = proto_m.group(1).strip()
    data_hex = data_m.group(1).strip()
    # For 125 kHz RFID, use protocol name as tag_type and data as UID
    tag_id = store.upsert_rfid_nfc_tag(
        tag_type=protocol, uid=data_hex, protocol="RFID",
        data_hex=data_hex,
    )
    return [{
        "type": "rfid_nfc_tag", "id": tag_id,
        "tag_type": protocol, "data_hex": data_hex,
    }]


# ---- Sub-GHz RX ----
# Signals come in blocks separated by blank lines:
#   Protocol: Princeton
#   Bit: 24
#   Key: 0x 00 AA BB
#   TE: 400
#   Freq: 433920000 Hz
_SUBGHZ_BLOCK_RE = re.compile(
    r"Protocol:\s*(.+?)\n"
    r".*?Key:\s*0x\s*([0-9A-Fa-f ]+?)\n"
    r".*?Freq:\s*(\d+)",
    re.DOTALL,
)


def parse_subghz(raw: str, store: TargetStore) -> list[dict]:
    """Parse Flipper subghz rx output, insert RF signals."""
    entities: list[dict] = []
    # Split on double-newline to handle multi-signal output
    blocks = re.split(r"\n\s*\n", raw)
    for block in blocks:
        m = _SUBGHZ_BLOCK_RE.search(block)
        if not m:
            continue
        protocol = m.group(1).strip()
        data_hex = m.group(2).strip()
        freq = int(m.group(3))

        sig_id = store.add_rf_signal(
            frequency_hz=freq, protocol=protocol,
            data_hex=data_hex, source_device="flipper",
        )
        entities.append({
            "type": "rf_signal", "id": sig_id,
            "protocol": protocol, "data_hex": data_hex,
            "frequency_hz": freq,
        })
    return entities


PARSER_MAP[("flipper", "nfc_detect")] = parse_nfc
PARSER_MAP[("flipper", "rfid_read")] = parse_rfid
PARSER_MAP[("flipper", "subghz_rx")] = parse_subghz
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_parser_flipper.py -v`
Expected: All 14 PASS

- [ ] **Step 5: Commit**

```bash
git add tools/parsers/flipper_rf.py tests/test_parser_flipper.py
git commit -m "feat(parsers): flipper NFC, RFID, SubGHz parsers"
```

---

### Task 6: Wire parsers into tool execute() methods

**Files:**

- Modify: `tools/blackarch.py` — add post-hook to `execute()`
- Modify: `tools/marauder.py` — add post-hook to `execute()`
- Modify: `tools/flipper.py` — add post-hook to `execute()`
- Modify: `tools/lg_tools.py` — inject `TargetStore` into tool instances
- Test: `tests/test_parser_wiring.py`

- [ ] **Step 1: Write failing integration test**

```python
# tests/test_parser_wiring.py
"""Integration tests: tool execute() auto-ingests to TargetStore."""
import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from knowledge.target_store import TargetStore


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22">
      <state state="open"/><service name="ssh"/>
    </port></ports>
  </host>
</nmaprun>"""


class TestBlackArchWiring:
    def test_nmap_auto_ingests_host(self, store):
        from tools.blackarch import BlackArchTool
        tool = BlackArchTool()
        tool._target_store = store
        with patch.object(tool, "_run", new_callable=AsyncMock, return_value=NMAP_XML):
            result = asyncio.get_event_loop().run_until_complete(
                tool.execute(action="nmap_scan", target="10.0.0.5")
            )
        # Raw output still returned to agent
        assert "<nmaprun>" in result
        # Host auto-ingested
        hosts = store.query_hosts(ip_prefix="10.0.0.")
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "10.0.0.5"


SCAN_APS = " SSID: TestNet, BSSID: AA:BB:CC:DD:EE:01, CH: 6, RSSI: -50, ENC: WPA2"


class TestMarauderWiring:
    def test_scan_aps_auto_ingests(self, store):
        from tools.marauder import MarauderTool
        conn = MagicMock()
        conn.send.return_value = SCAN_APS
        tool = MarauderTool(conn)
        tool._target_store = store
        result = asyncio.get_event_loop().run_until_complete(
            tool.execute(action="scan_aps")
        )
        assert "TestNet" in result
        assert store.get_stats()["wifi_networks"] == 1


NFC_OUTPUT = "NFC card detected\nType: NTAG215\nUID: 04:A3:2B:1C:7E:6D:80\nATQA: 44:00\nSAK: 00"


class TestFlipperWiring:
    def test_nfc_auto_ingests(self, store):
        from tools.flipper import FlipperTool
        conn = MagicMock()
        conn.send.return_value = NFC_OUTPUT
        tool = FlipperTool(conn)
        tool._target_store = store
        result = asyncio.get_event_loop().run_until_complete(
            tool.execute(action="nfc_detect")
        )
        assert "NTAG215" in result
        assert store.get_stats()["rfid_nfc_tags"] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_parser_wiring.py -v`
Expected: FAIL — tools don't have `_target_store` attribute handling, no parser calls

- [ ] **Step 3: Add post-hook to BlackArchTool.execute()**

In `tools/blackarch.py`, modify `execute()` to call the parser after getting the result:

```python
# At top of file, add import:
from tools.parsers import ingest_output

# In execute(), change the try block:
    try:
        result = await fn()
        ingest_output("blackarch", action, result, getattr(self, "_target_store", None))
        return result
    except Exception as exc:
        return f"BlackArch error ({action}): {exc}"
```

- [ ] **Step 4: Add post-hook to MarauderTool.execute()**

In `tools/marauder.py`, modify `execute()`:

```python
# At top of file, add import:
from tools.parsers import ingest_output

# In execute(), change the return:
    handler = dispatch.get(action)
    if handler is None:
        return f"Unknown action: {action}"
    result = handler()
    ingest_output("marauder", action, result, getattr(self, "_target_store", None))
    return result
```

- [ ] **Step 5: Add post-hook to FlipperTool.execute()**

In `tools/flipper.py`, modify `execute()`:

```python
# At top of file, add import:
from tools.parsers import ingest_output

# In execute(), change the return:
    handler = dispatch.get(action)
    if handler is None:
        return f"Unknown action: {action}"
    result = handler()
    ingest_output("flipper", action, result, getattr(self, "_target_store", None))
    return result
```

- [ ] **Step 6: Inject TargetStore into tool instances in lg_tools.py**

In `tools/lg_tools.py`, in `_init_pentest_singletons()`, after creating `_blackarch`:

```python
    _blackarch._target_store = _target_store
```

And in each `@tool` adapter that lazily creates flipper/marauder, after constructing the tool instance, inject the store:

```python
    # In the flipper @tool adapter, after _flipper = FlipperTool(conn):
    _flipper._target_store = _target_store

    # In the marauder @tool adapter, after _marauder = MarauderTool(conn):
    _marauder._target_store = _target_store
```

- [ ] **Step 7: Run all tests**

Run: `pytest tests/test_parser_wiring.py tests/test_parsers_dispatch.py tests/test_parser_nmap.py tests/test_parser_bettercap.py tests/test_parser_marauder.py tests/test_parser_flipper.py -v`
Expected: All PASS

- [ ] **Step 8: Run full test suite to verify no regressions**

Run: `pytest tests/ -v`
Expected: All existing tests still pass

- [ ] **Step 9: Commit**

```bash
git add tools/blackarch.py tools/marauder.py tools/flipper.py tools/lg_tools.py tests/test_parser_wiring.py
git commit -m "feat(parsers): wire parser post-hooks into tool execute() methods

BlackArch, Marauder, and Flipper tools now auto-ingest discovered
entities into TargetStore after every execute(). Parser errors are
swallowed — a broken parser never breaks a tool."
```

---

### Task 7: Full integration test — end-to-end pipeline

**Files:**

- Test: `tests/test_parser_e2e.py`

- [ ] **Step 1: Write end-to-end test**

```python
# tests/test_parser_e2e.py
"""End-to-end: tool output → parser → TargetStore → query back."""
import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from knowledge.target_store import TargetStore


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


FULL_NMAP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - 192.168.1.0/24">
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:00:00:01" addrtype="mac" vendor="Netgear"/>
    <hostnames><hostname name="gw.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
    </ports>
    <os><osmatch name="Linux 6.1" accuracy="98"/></os>
  </host>
  <host>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <address addr="AA:BB:CC:00:00:02" addrtype="mac" vendor="Raspberry Pi"/>
    <ports>
      <port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy"/></port>
    </ports>
  </host>
</nmaprun>"""


class TestE2EPipeline:
    def test_nmap_then_query(self, store):
        """Full pipeline: nmap XML → parse → store → query hosts and ports."""
        from tools.blackarch import BlackArchTool
        tool = BlackArchTool()
        tool._target_store = store

        with patch.object(tool, "_run", new_callable=AsyncMock, return_value=FULL_NMAP):
            asyncio.get_event_loop().run_until_complete(
                tool.execute(action="nmap_scan", target="192.168.1.0/24")
            )

        # Verify hosts
        hosts = store.query_hosts(ip_prefix="192.168.1.")
        assert len(hosts) == 2
        gw = next(h for h in hosts if h["ip"] == "192.168.1.1")
        assert gw["hostname"] == "gw.local"
        assert gw["os"] == "Linux 6.1"
        assert gw["vendor"] == "Netgear"

        # Verify ports
        ports = store.get_ports(gw["id"])
        assert len(ports) == 3
        services = {p["service"] for p in ports}
        assert services == {"ssh", "http", "https"}

        # Verify diff
        diff = store.diff_since("2000-01-01T00:00:00")
        assert diff["hosts"] == 2
        assert diff["ports"] == 4

    def test_multi_tool_convergence(self, store):
        """nmap discovers host, bettercap rediscovers same host — one row."""
        from tools.blackarch import BlackArchTool
        tool = BlackArchTool()
        tool._target_store = store

        nmap_xml = """<?xml version="1.0"?><nmaprun>
          <host><address addr="10.0.0.1" addrtype="ipv4"/>
            <address addr="DE:AD:BE:EF:00:01" addrtype="mac"/>
            <ports><port protocol="tcp" portid="22"><state state="open"/>
              <service name="ssh"/></port></ports></host>
        </nmaprun>"""

        bettercap_out = (
            "│ 10.0.0.1       │ DE:AD:BE:EF:00:01 │ router           "
            "│ Cisco            │  10k │   20k │"
        )

        with patch.object(tool, "_run", new_callable=AsyncMock, return_value=nmap_xml):
            asyncio.get_event_loop().run_until_complete(
                tool.execute(action="nmap_scan", target="10.0.0.1")
            )

        with patch.object(tool, "_run", new_callable=AsyncMock, return_value=bettercap_out):
            asyncio.get_event_loop().run_until_complete(
                tool.execute(action="bettercap_recon", interface="eth0")
            )

        hosts = store.query_hosts(ip_prefix="10.0.0.")
        assert len(hosts) == 1
        # bettercap enriched the vendor and hostname
        assert hosts[0]["vendor"] == "Cisco"
        assert hosts[0]["hostname"] == "router"
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/test_parser_e2e.py -v`
Expected: All PASS

- [ ] **Step 3: Run full suite**

Run: `pytest tests/ -v`
Expected: All tests pass, no regressions

- [ ] **Step 4: Commit**

```bash
git add tests/test_parser_e2e.py
git commit -m "test(parsers): end-to-end integration tests — multi-tool convergence"
```

---

## Summary

| Task | What | Tests |
|------|------|-------|
| 1 | Dispatcher + package scaffold | 4 tests |
| 2 | Nmap XML parser | 8 tests |
| 3 | Bettercap table parser | 7 tests |
| 4 | Marauder WiFi parser | 12 tests |
| 5 | Flipper RF parser | 14 tests |
| 6 | Wire into tool execute() | 3 tests |
| 7 | End-to-end integration | 2 tests |
| **Total** | | **50 tests** |
