"""Flipper Zero serial bridge tool.

Wraps all Flipper Zero CLI commands accessible over USB serial.
"""

from __future__ import annotations

from typing import Any

from tools._tool_base import Tool

from tools.device_manager import DeviceConnection


class FlipperTool(Tool):
    """Serial bridge for the Flipper Zero multi-tool."""

    def __init__(self, conn: DeviceConnection) -> None:
        self._conn = conn

    # ── Tool interface ─────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "flipper"

    @property
    def description(self) -> str:
        return (
            "Flipper Zero serial bridge. Provides access to SubGHz, NFC, RFID, "
            "IR, Bluetooth, storage, GPIO, and system commands via USB serial."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Method to invoke on the Flipper Zero.",
                    "enum": [
                        "subghz_rx", "subghz_tx", "subghz_tx_from_file", "subghz_decode_raw",
                        "nfc_detect", "nfc_field",
                        "rfid_read", "rfid_write", "rfid_emulate",
                        "ir_rx", "ir_tx", "ir_tx_raw", "ir_brute",
                        "bt_info",
                        "storage_list", "storage_read", "storage_stat",
                        "storage_mkdir", "storage_md5",
                        "gpio_set", "gpio_read",
                        "device_info", "power_info", "send_command",
                    ],
                },
                "freq": {"type": "number", "description": "Frequency in Hz."},
                "device": {"type": "integer", "description": "SubGHz device index (default 0)."},
                "key_hex": {"type": "string", "description": "Hex key for SubGHz TX."},
                "te": {"type": "integer", "description": "Timing element for SubGHz TX (default 400)."},
                "repeat": {"type": "integer", "description": "Repeat count."},
                "path": {"type": "string", "description": "File / directory path on Flipper SD."},
                "on": {"type": "boolean", "description": "Enable / disable flag."},
                "protocol": {"type": "string", "description": "Protocol name (RFID / IR)."},
                "data_hex": {"type": "string", "description": "Hex data for RFID write/emulate."},
                "address": {"type": "string", "description": "IR address."},
                "command": {"type": "string", "description": "IR command."},
                "raw_args": {"type": "string", "description": "Raw arguments for ir_tx_raw."},
                "remote_name": {"type": "string", "description": "Universal remote name."},
                "signal_name": {"type": "string", "description": "Signal name for IR brute."},
                "pin": {"type": "string", "description": "GPIO pin name."},
                "value": {"type": "integer", "description": "GPIO pin value (0 or 1)."},
                "cmd": {"type": "string", "description": "Raw CLI command to send."},
            },
            "required": ["action"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        dispatch = {
            "subghz_rx": lambda: self.subghz_rx(kwargs["freq"], kwargs.get("device", 0)),
            "subghz_tx": lambda: self.subghz_tx(
                kwargs["key_hex"], kwargs["freq"],
                te=kwargs.get("te", 400), repeat=kwargs.get("repeat", 3),
                device=kwargs.get("device", 0),
            ),
            "subghz_tx_from_file": lambda: self.subghz_tx_from_file(
                kwargs["path"], repeat=kwargs.get("repeat", 3),
                device=kwargs.get("device", 0),
            ),
            "subghz_decode_raw": lambda: self.subghz_decode_raw(kwargs["path"]),
            "nfc_detect": lambda: self.nfc_detect(),
            "nfc_field": lambda: self.nfc_field(kwargs["on"]),
            "rfid_read": lambda: self.rfid_read(protocol=kwargs.get("protocol")),
            "rfid_write": lambda: self.rfid_write(kwargs["protocol"], kwargs["data_hex"]),
            "rfid_emulate": lambda: self.rfid_emulate(kwargs["protocol"], kwargs["data_hex"]),
            "ir_rx": lambda: self.ir_rx(),
            "ir_tx": lambda: self.ir_tx(kwargs["protocol"], kwargs["address"], kwargs["command"]),
            "ir_tx_raw": lambda: self.ir_tx_raw(kwargs["raw_args"]),
            "ir_brute": lambda: self.ir_brute(kwargs["remote_name"], kwargs["signal_name"]),
            "bt_info": lambda: self.bt_info(),
            "storage_list": lambda: self.storage_list(kwargs["path"]),
            "storage_read": lambda: self.storage_read(kwargs["path"]),
            "storage_stat": lambda: self.storage_stat(kwargs["path"]),
            "storage_mkdir": lambda: self.storage_mkdir(kwargs["path"]),
            "storage_md5": lambda: self.storage_md5(kwargs["path"]),
            "gpio_set": lambda: self.gpio_set(kwargs["pin"], kwargs["value"]),
            "gpio_read": lambda: self.gpio_read(kwargs["pin"]),
            "device_info": lambda: self.device_info(),
            "power_info": lambda: self.power_info(),
            "send_command": lambda: self.send_command(kwargs["cmd"]),
        }
        handler = dispatch.get(action)
        if handler is None:
            return f"Unknown action: {action}"
        return handler()

    # ── SubGHz ─────────────────────────────────────────────────────

    def subghz_rx(self, freq: int | float, device: int = 0) -> str:
        return self._conn.send(f"subghz rx {freq} {device}")

    def subghz_tx(
        self,
        key_hex: str,
        freq: int | float,
        te: int = 400,
        repeat: int = 3,
        device: int = 0,
    ) -> str:
        return self._conn.send(
            f"subghz tx {key_hex} {freq} {te} {repeat} {device}"
        )

    def subghz_tx_from_file(
        self, path: str, repeat: int = 3, device: int = 0
    ) -> str:
        return self._conn.send(
            f"subghz tx_from_file {path} {repeat} {device}"
        )

    def subghz_decode_raw(self, path: str) -> str:
        return self._conn.send(f"subghz decode_raw {path}")

    # ── NFC ────────────────────────────────────────────────────────

    def nfc_detect(self) -> str:
        return self._conn.send("nfc detect")

    def nfc_field(self, on: bool) -> str:
        state = "on" if on else "off"
        return self._conn.send(f"nfc field {state}")

    # ── RFID ───────────────────────────────────────────────────────

    def rfid_read(self, protocol: str | None = None) -> str:
        cmd = "rfid read"
        if protocol:
            cmd += f" {protocol}"
        return self._conn.send(cmd)

    def rfid_write(self, protocol: str, data_hex: str) -> str:
        return self._conn.send(f"rfid write {protocol} {data_hex}")

    def rfid_emulate(self, protocol: str, data_hex: str) -> str:
        return self._conn.send(f"rfid emulate {protocol} {data_hex}")

    # ── IR ─────────────────────────────────────────────────────────

    def ir_rx(self) -> str:
        return self._conn.send("ir rx")

    def ir_tx(self, protocol: str, address: str, command: str) -> str:
        return self._conn.send(f"ir tx {protocol} {address} {command}")

    def ir_tx_raw(self, raw_args: str) -> str:
        return self._conn.send(f"ir tx_raw {raw_args}")

    def ir_brute(self, remote_name: str, signal_name: str) -> str:
        return self._conn.send(f"ir universal {remote_name} {signal_name}")

    # ── Bluetooth ──────────────────────────────────────────────────

    def bt_info(self) -> str:
        return self._conn.send("bt hci_info")

    # ── Storage ────────────────────────────────────────────────────

    def storage_list(self, path: str) -> str:
        return self._conn.send(f"storage list {path}")

    def storage_read(self, path: str) -> str:
        return self._conn.send(f"storage read {path}")

    def storage_stat(self, path: str) -> str:
        return self._conn.send(f"storage stat {path}")

    def storage_mkdir(self, path: str) -> str:
        return self._conn.send(f"storage mkdir {path}")

    def storage_md5(self, path: str) -> str:
        return self._conn.send(f"storage md5 {path}")

    # ── GPIO ───────────────────────────────────────────────────────

    def gpio_set(self, pin: str, value: int) -> str:
        self._conn.send(f"gpio mode {pin} 0")
        return self._conn.send(f"gpio set {pin} {value}")

    def gpio_read(self, pin: str) -> str:
        self._conn.send(f"gpio mode {pin} 1")
        return self._conn.send(f"gpio read {pin}")

    # ── System ─────────────────────────────────────────────────────

    def device_info(self) -> str:
        return self._conn.send("!")

    def power_info(self) -> str:
        return self._conn.send("power info")

    def send_command(self, cmd: str) -> str:
        return self._conn.send(cmd)
