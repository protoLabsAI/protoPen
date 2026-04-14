"""Tests for the TargetStore — CRUD, upsert, query, diff."""

import pytest

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
        diff = store.diff_since("2000-01-01T00:00:00Z")
        assert diff["new_hosts"] == 1

    def test_diff_shows_new_ports(self, store):
        hid = store.upsert_host(ip="192.168.1.1")
        store.upsert_port(host_id=hid, port=22)
        diff = store.diff_since("2000-01-01T00:00:00Z")
        assert diff["new_ports"] == 1
