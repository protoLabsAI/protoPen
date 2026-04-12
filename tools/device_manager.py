"""Device manager — USB device discovery, serial connection lifecycle, health checks.

Manages connections to PortaPack H4M, Flipper Zero, ESP32 Marauder,
and WiFi adapter. Uses USB serial numbers for stable device identification
when available, falls back to configured port paths.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import serial

logger = logging.getLogger(__name__)


@dataclass
class DeviceStatus:
    name: str
    connected: bool
    port: Optional[str] = None
    error: Optional[str] = None


@dataclass
class DeviceConnection:
    name: str
    port: str
    ser: serial.Serial
    prompt: str = ""
    timeout: float = 3

    @property
    def is_connected(self) -> bool:
        return self.ser is not None and self.ser.is_open

    def send(self, cmd: str) -> str:
        """Send a text command and read until the device prompt."""
        if not self.is_connected:
            raise ConnectionError(f"{self.name} is not connected")
        self.ser.reset_input_buffer()
        self.ser.write(f"{cmd}\r\n".encode())
        raw = self.ser.read_until(self.prompt.encode())
        response = raw.decode(errors="replace")
        lines = response.split("\r\n")
        body = "\r\n".join(lines[1:])
        if body.endswith(self.prompt):
            body = body[: -len(self.prompt)]
        return body.strip()

    def send_raw(self, data: bytes) -> bytes:
        """Send raw bytes and read response."""
        if not self.is_connected:
            raise ConnectionError(f"{self.name} is not connected")
        self.ser.write(data)
        return self.ser.read(4096)

    def close(self):
        if self.ser and self.ser.is_open:
            self.ser.close()


class DeviceManager:
    """Manages serial connections to all pen testing hardware."""

    def __init__(self, device_configs: dict):
        self._configs = device_configs
        self._connections: dict[str, DeviceConnection] = {}

    def list_devices(self) -> list[str]:
        return list(self._configs.keys())

    def connect(self, device_name: str) -> DeviceConnection:
        if device_name not in self._configs:
            raise KeyError(f"Unknown device: {device_name}")

        cfg = self._configs[device_name]

        if cfg.get("type") == "network":
            conn = DeviceConnection(
                name=device_name,
                port=cfg.get("interface", ""),
                ser=None,
                prompt="",
            )
            self._connections[device_name] = conn
            return conn

        port = self._resolve_port(device_name, cfg)
        baud = cfg.get("baud_rate", 0)
        timeout = cfg.get("timeout", 3)
        prompt = cfg.get("prompt", "")

        try:
            ser = serial.Serial(port, baudrate=baud or 9600, timeout=timeout)
            conn = DeviceConnection(
                name=device_name,
                port=port,
                ser=ser,
                prompt=prompt,
                timeout=timeout,
            )
            if prompt:
                try:
                    ser.read_until(prompt.encode())
                except serial.SerialTimeoutException:
                    pass
            self._connections[device_name] = conn
            logger.info("Connected to %s on %s", device_name, port)
            return conn
        except serial.SerialException as exc:
            raise ConnectionError(
                f"Failed to connect to {device_name} on {port}: {exc}"
            )

    def _resolve_port(self, name: str, cfg: dict) -> str:
        sn = cfg.get("serial_number", "")
        if sn:
            port = self._find_port_by_serial(sn)
            if port:
                return port
            logger.warning(
                "Device %s serial number %s not found, falling back to %s",
                name, sn, cfg.get("fallback_port"),
            )
        return cfg.get("fallback_port", "/dev/ttyACM0")

    def _find_port_by_serial(self, serial_number: str) -> Optional[str]:
        try:
            from serial.tools.list_ports import comports
            for port_info in comports():
                if port_info.serial_number == serial_number:
                    return port_info.device
        except Exception:
            pass
        return None

    def disconnect(self, device_name: str):
        conn = self._connections.pop(device_name, None)
        if conn:
            conn.close()
            logger.info("Disconnected %s", device_name)

    def disconnect_all(self):
        for name in list(self._connections):
            self.disconnect(name)

    def get(self, device_name: str) -> Optional[DeviceConnection]:
        return self._connections.get(device_name)

    def is_connected(self, device_name: str) -> bool:
        conn = self._connections.get(device_name)
        return conn is not None and conn.is_connected

    def health_check(self, device_name: str) -> DeviceStatus:
        conn = self._connections.get(device_name)
        if conn is None or not conn.is_connected:
            return DeviceStatus(name=device_name, connected=False)
        return DeviceStatus(name=device_name, connected=True, port=conn.port)

    def all_status(self) -> list[DeviceStatus]:
        return [self.health_check(name) for name in self._configs]
