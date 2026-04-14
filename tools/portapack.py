"""PortaPack H4M Mayhem serial bridge.

Wraps the Mayhem firmware's USB CDC serial console (ch> shell) as a LangGraph Tool
with methods for RF scanning, app control, signal capture/replay, screen reading,
and transmission.

Protocol: text commands over USB CDC virtual serial port.
Prompt: 'ch>'
"""
from __future__ import annotations

import logging
from typing import Any

from tools._tool_base import Tool

from tools.device_manager import DeviceConnection

logger = logging.getLogger(__name__)

BTN_RIGHT = 1
BTN_LEFT = 2
BTN_DOWN = 3
BTN_UP = 4
BTN_SELECT = 5
BTN_DFU = 6
BTN_ROTARY_LEFT = 7
BTN_ROTARY_RIGHT = 8


class PortaPackTool(Tool):
    """Controls a PortaPack H4M running Mayhem firmware via USB serial."""

    def __init__(self, conn: DeviceConnection):
        self._conn = conn

    @property
    def name(self) -> str:
        return "portapack"

    @property
    def description(self) -> str:
        return (
            "Control a PortaPack H4M (HackRF One + Mayhem firmware) for RF operations. "
            "Supports spectrum scanning, signal capture/replay, protocol decoding "
            "(ADS-B, POCSAG, BLE, TPMS, etc.), transmission, and device UI control. "
            "Frequency range: 1 MHz - 6 GHz."
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
                        "list_apps", "start_app", "set_frequency",
                        "radio_info", "read_screen", "screenshot",
                        "tap", "press_button", "system_info",
                        "send_pocsag", "send_command",
                        "file_list", "reboot",
                    ],
                },
                "app_name": {"type": "string", "description": "App short name (from list_apps)"},
                "frequency_hz": {"type": "integer", "description": "Frequency in Hz"},
                "x": {"type": "integer", "description": "Touch X coordinate (0-240)"},
                "y": {"type": "integer", "description": "Touch Y coordinate (0-320)"},
                "button": {
                    "type": "integer",
                    "description": "Button ID: 1=Right 2=Left 3=Down 4=Up 5=Select 7=RotaryL 8=RotaryR",
                },
                "address": {"type": "integer", "description": "POCSAG address"},
                "message": {"type": "string", "description": "POCSAG message text"},
                "command": {"type": "string", "description": "Raw serial command for send_command"},
                "path": {"type": "string", "description": "SD card path for file_list"},
            },
            "required": ["action"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        dispatch = {
            "list_apps": lambda: self.list_apps(),
            "start_app": lambda: self.start_app(kwargs.get("app_name", "")),
            "set_frequency": lambda: self.set_frequency(kwargs.get("frequency_hz", 0)),
            "radio_info": lambda: self.get_radio_info(),
            "read_screen": lambda: self.read_screen(),
            "screenshot": lambda: self.screenshot(),
            "tap": lambda: self.tap(kwargs.get("x", 0), kwargs.get("y", 0)),
            "press_button": lambda: self.press_button(kwargs.get("button", BTN_SELECT)),
            "system_info": lambda: self.system_info(),
            "send_pocsag": lambda: self.send_pocsag(
                kwargs.get("address", 0), kwargs.get("message", "")
            ),
            "send_command": lambda: self.send_command(kwargs.get("command", "")),
            "file_list": lambda: self.file_list(kwargs.get("path", "/")),
            "reboot": lambda: self.send_command("reboot"),
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            return fn()
        except Exception as exc:
            return f"PortaPack error ({action}): {exc}"

    def list_apps(self) -> str:
        return self._conn.send("applist")

    def start_app(self, name: str) -> str:
        return self._conn.send(f"appstart {name}")

    def set_frequency(self, hz: int) -> str:
        return self._conn.send(f"setfreq {hz}")

    def get_radio_info(self) -> str:
        return self._conn.send("radioinfo")

    def read_screen(self) -> str:
        return self._conn.send("accessibility_readall")

    def read_focused(self) -> str:
        return self._conn.send("accessibility_readcurr")

    def screenshot(self) -> str:
        return self._conn.send("screenframeshort")

    def tap(self, x: int, y: int) -> str:
        return self._conn.send(f"touch {x} {y}")

    def press_button(self, button: int) -> str:
        return self._conn.send(f"button {button}")

    def system_info(self) -> str:
        return self._conn.send("sysinfo")

    def send_pocsag(self, address: int, message: str) -> str:
        cmd = f"sendpocsag {address} {len(message)}"
        self._conn.ser.reset_input_buffer()
        self._conn.ser.write(f"{cmd}\r\n".encode())
        self._conn.ser.write(message.encode())
        raw = self._conn.ser.read_until(self._conn.prompt.encode())
        return raw.decode(errors="replace").strip()

    def send_command(self, command: str) -> str:
        return self._conn.send(command)

    def file_list(self, path: str = "/") -> str:
        return self._conn.send(f"ls {path}")

    def inject_gps(self, lat: float, lon: float, alt: float = 0, speed: float = 0) -> str:
        return self._conn.send(f"gotgps {lat} {lon} {alt} {speed}")

    def inject_orientation(self, degrees: float) -> str:
        return self._conn.send(f"gotorientation {degrees}")
