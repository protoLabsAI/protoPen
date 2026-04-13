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
