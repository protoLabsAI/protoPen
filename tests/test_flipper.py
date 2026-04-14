"""Comprehensive tests for FlipperTool serial bridge."""

from __future__ import annotations

import asyncio
import sys
from unittest.mock import MagicMock, call

import pytest

# ── Stub DeviceConnection before importing the tool ────────────────
if "tools.device_manager" not in sys.modules:
    _dm_mod = type(sys)("tools.device_manager")
    _dm_mod.DeviceConnection = MagicMock
    sys.modules["tools.device_manager"] = _dm_mod

from tools.flipper import FlipperTool  # noqa: E402


# ── Fixtures ───────────────────────────────────────────────────────

@pytest.fixture()
def conn() -> MagicMock:
    mock = MagicMock()
    mock.is_connected = True
    mock.name = "flipper"
    mock.prompt = ">: "
    mock.send = MagicMock(return_value="OK\r\n")
    return mock


@pytest.fixture()
def flipper(conn: MagicMock) -> FlipperTool:
    return FlipperTool(conn)


# ── Tool interface ─────────────────────────────────────────────────

class TestToolInterface:
    def test_name(self, flipper: FlipperTool) -> None:
        assert flipper.name == "flipper"

    def test_description_is_nonempty(self, flipper: FlipperTool) -> None:
        assert isinstance(flipper.description, str)
        assert len(flipper.description) > 10

    def test_parameters_schema(self, flipper: FlipperTool) -> None:
        p = flipper.parameters
        assert p["type"] == "object"
        assert "action" in p["properties"]
        assert "action" in p["required"]

    def test_execute_unknown_action(self, flipper: FlipperTool) -> None:
        result = asyncio.get_event_loop().run_until_complete(
            flipper.execute(action="nope")
        )
        assert "Unknown action" in result


# ── SubGHz ─────────────────────────────────────────────────────────

class TestSubGHz:
    def test_subghz_rx(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.subghz_rx(433920000, 0)
        conn.send.assert_called_with("subghz rx 433920000 0")

    def test_subghz_rx_default_device(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.subghz_rx(315000000)
        conn.send.assert_called_with("subghz rx 315000000 0")

    def test_subghz_tx(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.subghz_tx("DEADBEEF", 433920000, te=400, repeat=3, device=0)
        conn.send.assert_called_with("subghz tx DEADBEEF 433920000 400 3 0")

    def test_subghz_tx_defaults(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.subghz_tx("AA", 315000000)
        conn.send.assert_called_with("subghz tx AA 315000000 400 3 0")

    def test_subghz_tx_from_file(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.subghz_tx_from_file("/ext/subghz/cap.sub", repeat=5, device=1)
        conn.send.assert_called_with("subghz tx_from_file /ext/subghz/cap.sub 5 1")

    def test_subghz_tx_from_file_defaults(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.subghz_tx_from_file("/ext/test.sub")
        conn.send.assert_called_with("subghz tx_from_file /ext/test.sub 3 0")

    def test_subghz_decode_raw(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.subghz_decode_raw("/ext/raw.sub")
        conn.send.assert_called_with("subghz decode_raw /ext/raw.sub")

    def test_subghz_bruteforce(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.subghz_bruteforce("/ext/brute.sub", 433920000, repeat=5, device=0)
        conn.send.assert_called_with("subghz tx_from_file /ext/brute.sub 5 0")

    def test_subghz_bruteforce_defaults(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.subghz_bruteforce("/ext/brute.sub", 315000000)
        conn.send.assert_called_with("subghz tx_from_file /ext/brute.sub 3 0")


# ── NFC ────────────────────────────────────────────────────────────

class TestNFC:
    def test_nfc_detect(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.nfc_detect()
        conn.send.assert_called_with("nfc detect")

    def test_nfc_field_on(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.nfc_field(True)
        conn.send.assert_called_with("nfc field on")

    def test_nfc_field_off(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.nfc_field(False)
        conn.send.assert_called_with("nfc field off")

    def test_nfc_emulate(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.nfc_emulate("/ext/nfc/card.nfc")
        conn.send.assert_called_with("nfc emulate /ext/nfc/card.nfc")


# ── RFID ───────────────────────────────────────────────────────────

class TestRFID:
    def test_rfid_read_no_protocol(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.rfid_read()
        conn.send.assert_called_with("rfid read")

    def test_rfid_read_with_protocol(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.rfid_read(protocol="EM4100")
        conn.send.assert_called_with("rfid read EM4100")

    def test_rfid_write(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.rfid_write("EM4100", "AABBCCDDEE")
        conn.send.assert_called_with("rfid write EM4100 AABBCCDDEE")

    def test_rfid_emulate(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.rfid_emulate("HIDProx", "0102030405")
        conn.send.assert_called_with("rfid emulate HIDProx 0102030405")


# ── IR ─────────────────────────────────────────────────────────────

class TestIR:
    def test_ir_rx(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.ir_rx()
        conn.send.assert_called_with("ir rx")

    def test_ir_tx(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.ir_tx("NEC", "0x04", "0x08")
        conn.send.assert_called_with("ir tx NEC 0x04 0x08")

    def test_ir_tx_raw(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.ir_tx_raw("9000 4500 560 1690 560")
        conn.send.assert_called_with("ir tx_raw 9000 4500 560 1690 560")

    def test_ir_brute(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.ir_brute("tv", "power")
        conn.send.assert_called_with("ir universal tv power")


# ── Bluetooth / BLE ────────────────────────────────────────────────

class TestBluetooth:
    def test_bt_info(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.bt_info()
        conn.send.assert_called_with("bt hci_info")

    def test_ble_scan(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.ble_scan(timeout=15)
        conn.send.assert_called_with("bt scan 15")

    def test_ble_scan_default_timeout(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.ble_scan()
        conn.send.assert_called_with("bt scan 10")


# ── Storage ────────────────────────────────────────────────────────

class TestStorage:
    def test_storage_list(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.storage_list("/ext")
        conn.send.assert_called_with("storage list /ext")

    def test_storage_read(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.storage_read("/ext/test.txt")
        conn.send.assert_called_with("storage read /ext/test.txt")

    def test_storage_stat(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.storage_stat("/ext")
        conn.send.assert_called_with("storage stat /ext")

    def test_storage_mkdir(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.storage_mkdir("/ext/new_dir")
        conn.send.assert_called_with("storage mkdir /ext/new_dir")

    def test_storage_md5(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.storage_md5("/ext/file.bin")
        conn.send.assert_called_with("storage md5 /ext/file.bin")


# ── GPIO ───────────────────────────────────────────────────────────

class TestGPIO:
    def test_gpio_set(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.gpio_set("PA7", 1)
        assert conn.send.call_args_list == [
            call("gpio mode PA7 0"),
            call("gpio set PA7 1"),
        ]

    def test_gpio_set_low(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.gpio_set("PA6", 0)
        assert conn.send.call_args_list == [
            call("gpio mode PA6 0"),
            call("gpio set PA6 0"),
        ]

    def test_gpio_read(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.gpio_read("PA4")
        assert conn.send.call_args_list == [
            call("gpio mode PA4 1"),
            call("gpio read PA4"),
        ]


# ── System ─────────────────────────────────────────────────────────

class TestSystem:
    def test_device_info(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.device_info()
        conn.send.assert_called_with("!")

    def test_power_info(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.power_info()
        conn.send.assert_called_with("power info")

    def test_send_command(self, flipper: FlipperTool, conn: MagicMock) -> None:
        flipper.send_command("update")
        conn.send.assert_called_with("update")


# ── Execute dispatch ───────────────────────────────────────────────

class TestExecuteDispatch:
    """Verify async execute() routes to every method correctly."""

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_dispatch_subghz_rx(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="subghz_rx", freq=433920000, device=0))
        conn.send.assert_called_with("subghz rx 433920000 0")

    def test_dispatch_subghz_tx(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="subghz_tx", key_hex="FF", freq=315000000))
        conn.send.assert_called_with("subghz tx FF 315000000 400 3 0")

    def test_dispatch_nfc_detect(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="nfc_detect"))
        conn.send.assert_called_with("nfc detect")

    def test_dispatch_nfc_field(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="nfc_field", on=False))
        conn.send.assert_called_with("nfc field off")

    def test_dispatch_rfid_read(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="rfid_read"))
        conn.send.assert_called_with("rfid read")

    def test_dispatch_rfid_write(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="rfid_write", protocol="EM4100", data_hex="AA"))
        conn.send.assert_called_with("rfid write EM4100 AA")

    def test_dispatch_ir_rx(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="ir_rx"))
        conn.send.assert_called_with("ir rx")

    def test_dispatch_ir_tx(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="ir_tx", protocol="NEC", address="0x04", command="0x08"))
        conn.send.assert_called_with("ir tx NEC 0x04 0x08")

    def test_dispatch_ir_brute(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="ir_brute", remote_name="tv", signal_name="power"))
        conn.send.assert_called_with("ir universal tv power")

    def test_dispatch_bt_info(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="bt_info"))
        conn.send.assert_called_with("bt hci_info")

    def test_dispatch_storage_list(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="storage_list", path="/ext"))
        conn.send.assert_called_with("storage list /ext")

    def test_dispatch_storage_md5(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="storage_md5", path="/ext/f.bin"))
        conn.send.assert_called_with("storage md5 /ext/f.bin")

    def test_dispatch_gpio_set(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="gpio_set", pin="PA7", value=1))
        assert conn.send.call_args_list == [
            call("gpio mode PA7 0"),
            call("gpio set PA7 1"),
        ]

    def test_dispatch_gpio_read(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="gpio_read", pin="PA4"))
        assert conn.send.call_args_list == [
            call("gpio mode PA4 1"),
            call("gpio read PA4"),
        ]

    def test_dispatch_device_info(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="device_info"))
        conn.send.assert_called_with("!")

    def test_dispatch_power_info(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="power_info"))
        conn.send.assert_called_with("power info")

    def test_dispatch_send_command(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="send_command", cmd="led red 255"))
        conn.send.assert_called_with("led red 255")

    def test_dispatch_returns_send_value(self, flipper: FlipperTool, conn: MagicMock) -> None:
        conn.send.return_value = "Flipper Zero v0.89"
        result = self._run(flipper.execute(action="device_info"))
        assert result == "Flipper Zero v0.89"

    def test_dispatch_subghz_decode_raw(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="subghz_decode_raw", path="/ext/raw.sub"))
        conn.send.assert_called_with("subghz decode_raw /ext/raw.sub")

    def test_dispatch_rfid_emulate(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="rfid_emulate", protocol="HIDProx", data_hex="0102"))
        conn.send.assert_called_with("rfid emulate HIDProx 0102")

    def test_dispatch_ir_tx_raw(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="ir_tx_raw", raw_args="9000 4500"))
        conn.send.assert_called_with("ir tx_raw 9000 4500")

    def test_dispatch_storage_read(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="storage_read", path="/ext/t.txt"))
        conn.send.assert_called_with("storage read /ext/t.txt")

    def test_dispatch_storage_stat(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="storage_stat", path="/ext"))
        conn.send.assert_called_with("storage stat /ext")

    def test_dispatch_storage_mkdir(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="storage_mkdir", path="/ext/new"))
        conn.send.assert_called_with("storage mkdir /ext/new")

    def test_dispatch_subghz_tx_from_file(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="subghz_tx_from_file", path="/ext/cap.sub"))
        conn.send.assert_called_with("subghz tx_from_file /ext/cap.sub 3 0")

    def test_dispatch_subghz_bruteforce(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="subghz_bruteforce", path="/ext/bf.sub", freq=433920000))
        conn.send.assert_called_with("subghz tx_from_file /ext/bf.sub 3 0")

    def test_dispatch_nfc_emulate(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="nfc_emulate", path="/ext/nfc/card.nfc"))
        conn.send.assert_called_with("nfc emulate /ext/nfc/card.nfc")

    def test_dispatch_ble_scan(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="ble_scan", timeout=20))
        conn.send.assert_called_with("bt scan 20")

    def test_dispatch_ble_scan_default(self, flipper: FlipperTool, conn: MagicMock) -> None:
        self._run(flipper.execute(action="ble_scan"))
        conn.send.assert_called_with("bt scan 10")
