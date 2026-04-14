"""Comprehensive tests for MarauderTool serial bridge."""

from __future__ import annotations

import asyncio
import sys
from unittest.mock import MagicMock

import pytest

# ── Stub DeviceConnection before importing the tool ────────────────
if "tools.device_manager" not in sys.modules:
    _dm_mod = type(sys)("tools.device_manager")
    _dm_mod.DeviceConnection = MagicMock
    sys.modules["tools.device_manager"] = _dm_mod

from tools.marauder import MarauderTool  # noqa: E402


# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture()
def conn() -> MagicMock:
    mock = MagicMock()
    mock.is_connected = True
    mock.name = "marauder"
    mock.prompt = "> "
    mock.send = MagicMock(return_value="OK\r\n")
    return mock


@pytest.fixture()
def marauder(conn: MagicMock) -> MarauderTool:
    return MarauderTool(conn)


# ── Tool interface ─────────────────────────────────────────────────


class TestToolInterface:
    def test_name(self, marauder: MarauderTool) -> None:
        assert marauder.name == "marauder"

    def test_description_is_nonempty(self, marauder: MarauderTool) -> None:
        assert isinstance(marauder.description, str)
        assert len(marauder.description) > 10

    def test_parameters_schema(self, marauder: MarauderTool) -> None:
        p = marauder.parameters
        assert p["type"] == "object"
        assert "action" in p["properties"]
        assert "action" in p["required"]

    def test_execute_unknown_action(self, marauder: MarauderTool) -> None:
        result = asyncio.get_event_loop().run_until_complete(marauder.execute(action="nope"))
        assert "Unknown action" in result


# ── Scanning ───────────────────────────────────────────────────────


class TestScanning:
    def test_scan_aps(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.scan_aps()
        conn.send.assert_called_with("scanap")

    def test_scan_stations(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.scan_stations()
        conn.send.assert_called_with("scansta")

    def test_stop(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.stop()
        conn.send.assert_called_with("stopscan")

    def test_list_results_aps(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.list_results("aps")
        conn.send.assert_called_with("list -a")

    def test_list_results_stations(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.list_results("stations")
        conn.send.assert_called_with("list -c")

    def test_list_results_ssids(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.list_results("ssids")
        conn.send.assert_called_with("list -s")

    def test_list_results_default(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.list_results()
        conn.send.assert_called_with("list -a")

    def test_list_results_unknown_kind_fallback(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.list_results("unknown")
        conn.send.assert_called_with("list -a")

    def test_select_targets(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.select_targets([0, 2, 3])
        conn.send.assert_called_with("select -a 0,2,3")

    def test_select_targets_single(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.select_targets([5])
        conn.send.assert_called_with("select -a 5")

    def test_select_targets_empty(self, marauder: MarauderTool, conn: MagicMock) -> None:
        result = marauder.select_targets([])
        assert "No indices" in result

    def test_select_targets_none(self, marauder: MarauderTool, conn: MagicMock) -> None:
        result = marauder.select_targets(None)
        assert "No indices" in result

    def test_select_all(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.select_all()
        conn.send.assert_called_with("select -a all")

    def test_set_channel(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.set_channel(6)
        conn.send.assert_called_with("channel 6")

    def test_clear_list(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.clear_list()
        conn.send.assert_called_with("clearlist")


# ── Attacks ────────────────────────────────────────────────────────


class TestAttacks:
    def test_deauth(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.deauth()
        conn.send.assert_called_with("attack -t deauth")

    def test_beacon_spam(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.beacon_spam()
        conn.send.assert_called_with("attack -t beacon -l")

    def test_probe_flood(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.probe_flood()
        conn.send.assert_called_with("attack -t probe")

    def test_rickroll(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.rickroll()
        conn.send.assert_called_with("attack -t rickroll")


# ── Sniffing ───────────────────────────────────────────────────────


class TestSniffing:
    def test_sniff_pmkid_default(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.sniff_pmkid()
        conn.send.assert_called_with("sniffpmkid")

    def test_sniff_pmkid_with_deauth(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.sniff_pmkid(deauth=True)
        conn.send.assert_called_with("sniffpmkid -d")

    def test_sniff_deauth(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.sniff_deauth()
        conn.send.assert_called_with("sniffdeauth")

    def test_sniff_beacon(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.sniff_beacon()
        conn.send.assert_called_with("sniffbeacon")

    def test_sniff_raw(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.sniff_raw()
        conn.send.assert_called_with("sniffraw")


# ── BLE ────────────────────────────────────────────────────────────


class TestBLE:
    def test_bt_spam_all(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.bt_spam_all()
        conn.send.assert_called_with("blespam")

    def test_sour_apple(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.sour_apple()
        conn.send.assert_called_with("sourapple")

    def test_swift_pair(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.swift_pair()
        conn.send.assert_called_with("swiftpair")

    def test_samsung_ble_spam(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.samsung_ble_spam()
        conn.send.assert_called_with("samsungblespam")


# ── Advanced ───────────────────────────────────────────────────────


class TestAdvanced:
    def test_evil_portal_no_path(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.evil_portal()
        conn.send.assert_called_with("evilportal")

    def test_evil_portal_with_path(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.evil_portal(html_path="/sd/portal.html")
        conn.send.assert_called_with("evilportal /sd/portal.html")

    def test_karma(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.karma()
        conn.send.assert_called_with("karma")

    def test_ssid_add(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.ssid_add("FreeWiFi")
        conn.send.assert_called_with('ssid -a -n "FreeWiFi"')

    def test_ssid_add_with_spaces(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.ssid_add("Free Guest WiFi")
        conn.send.assert_called_with('ssid -a -n "Free Guest WiFi"')

    def test_ssid_generate(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.ssid_generate(20)
        conn.send.assert_called_with("ssid -a -g 20")


# ── System ─────────────────────────────────────────────────────────


class TestSystem:
    def test_info(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.info()
        conn.send.assert_called_with("info")

    def test_send_command(self, marauder: MarauderTool, conn: MagicMock) -> None:
        marauder.send_command("reboot")
        conn.send.assert_called_with("reboot")


# ── Execute dispatch ───────────────────────────────────────────────


class TestExecuteDispatch:
    """Verify async execute() routes to every method correctly."""

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_dispatch_scan_aps(self, marauder: MarauderTool, conn: MagicMock) -> None:
        self._run(marauder.execute(action="scan_aps"))
        conn.send.assert_called_with("scanap")

    def test_dispatch_stop(self, marauder: MarauderTool, conn: MagicMock) -> None:
        self._run(marauder.execute(action="stop"))
        conn.send.assert_called_with("stopscan")

    def test_dispatch_deauth(self, marauder: MarauderTool, conn: MagicMock) -> None:
        self._run(marauder.execute(action="deauth"))
        conn.send.assert_called_with("attack -t deauth")

    def test_dispatch_sniff_pmkid(self, marauder: MarauderTool, conn: MagicMock) -> None:
        self._run(marauder.execute(action="sniff_pmkid", deauth=True))
        conn.send.assert_called_with("sniffpmkid -d")

    def test_dispatch_evil_portal(self, marauder: MarauderTool, conn: MagicMock) -> None:
        self._run(marauder.execute(action="evil_portal", html_path="/sd/p.html"))
        conn.send.assert_called_with("evilportal /sd/p.html")

    def test_dispatch_ssid_add(self, marauder: MarauderTool, conn: MagicMock) -> None:
        self._run(marauder.execute(action="ssid_add", name="TestNet"))
        conn.send.assert_called_with('ssid -a -n "TestNet"')

    def test_dispatch_info(self, marauder: MarauderTool, conn: MagicMock) -> None:
        self._run(marauder.execute(action="info"))
        conn.send.assert_called_with("info")

    def test_dispatch_returns_send_value(self, marauder: MarauderTool, conn: MagicMock) -> None:
        conn.send.return_value = "Marauder v0.13"
        result = self._run(marauder.execute(action="info"))
        assert result == "Marauder v0.13"

    def test_dispatch_select_targets(self, marauder: MarauderTool, conn: MagicMock) -> None:
        self._run(marauder.execute(action="select_targets", indices=[1, 4]))
        conn.send.assert_called_with("select -a 1,4")

    def test_dispatch_set_channel(self, marauder: MarauderTool, conn: MagicMock) -> None:
        self._run(marauder.execute(action="set_channel", ch=11))
        conn.send.assert_called_with("channel 11")

    def test_dispatch_bt_spam_all(self, marauder: MarauderTool, conn: MagicMock) -> None:
        self._run(marauder.execute(action="bt_spam_all"))
        conn.send.assert_called_with("blespam")
