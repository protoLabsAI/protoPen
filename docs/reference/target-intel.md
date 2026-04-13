# Target Intelligence Schema

The target intelligence database is a SQLite store that tracks all discovered entities across all sensor platforms (nmap, Marauder, Flipper Zero, PortaPack, aircrack-ng, bettercap). It lives at `/sandbox/knowledge/targets.db`.

All tables use `first_seen` / `last_seen` timestamps for temporal tracking. Upsert operations update `last_seen` on conflict, preserving `first_seen`.

## Tables

### scan_sessions

Temporal grouping for every scan/capture operation.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-incrementing session ID |
| `engagement` | TEXT | Engagement name |
| `tool` | TEXT NOT NULL | Tool that performed the scan |
| `action` | TEXT NOT NULL | Tool action (e.g. `nmap_scan`, `scan_aps`) |
| `started_at` | TEXT NOT NULL | ISO 8601 timestamp |
| `ended_at` | TEXT | ISO 8601 timestamp (NULL while running) |
| `raw_output` | TEXT | Raw tool output |
| `notes` | TEXT | Free-form notes |

### hosts

Central entity -- anything with an IP or MAC address.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-incrementing host ID |
| `ip` | TEXT | IPv4 address |
| `mac` | TEXT | MAC address |
| `hostname` | TEXT | Resolved hostname |
| `os` | TEXT | Detected operating system |
| `vendor` | TEXT | NIC vendor (from OUI lookup) |
| `device_type` | TEXT | Device classification (default `unknown`) |
| `tags` | TEXT | JSON array of tags |
| `first_seen` | TEXT NOT NULL | First discovery timestamp |
| `last_seen` | TEXT NOT NULL | Last activity timestamp |
| `scan_session_id` | INTEGER FK | Reference to scan_sessions |
| `notes` | TEXT | Free-form notes |

**Unique constraint:** `(ip, mac)`

**Indexes:** `ip`, `mac`, `last_seen`

### ports

Services discovered on hosts.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-incrementing port ID |
| `host_id` | INTEGER FK NOT NULL | Reference to hosts (CASCADE delete) |
| `port` | INTEGER NOT NULL | Port number |
| `protocol` | TEXT NOT NULL | Protocol (default `tcp`) |
| `state` | TEXT NOT NULL | Port state (default `open`) |
| `service` | TEXT | Service name |
| `banner` | TEXT | Service banner / version string |
| `first_seen` | TEXT NOT NULL | First discovery timestamp |
| `last_seen` | TEXT NOT NULL | Last activity timestamp |
| `scan_session_id` | INTEGER FK | Reference to scan_sessions |

**Unique constraint:** `(host_id, port, protocol)`

### wifi_networks

Access points discovered by Marauder, aircrack-ng, or bettercap.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-incrementing network ID |
| `bssid` | TEXT NOT NULL | AP MAC address |
| `ssid` | TEXT | Network name |
| `channel` | INTEGER | WiFi channel |
| `rssi` | INTEGER | Signal strength (dBm) |
| `encryption` | TEXT | Encryption type (WPA2, WPA3, Open, etc.) |
| `wps` | INTEGER | WPS enabled flag (default 0) |
| `host_id` | INTEGER FK | Reference to hosts |
| `first_seen` | TEXT NOT NULL | First discovery timestamp |
| `last_seen` | TEXT NOT NULL | Last activity timestamp |
| `scan_session_id` | INTEGER FK | Reference to scan_sessions |
| `notes` | TEXT | Free-form notes |

**Unique constraint:** `(bssid)`

### wifi_stations

Client devices associated (or probing) to APs.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-incrementing station ID |
| `mac` | TEXT NOT NULL | Station MAC address |
| `network_id` | INTEGER FK | Reference to wifi_networks |
| `rssi` | INTEGER | Signal strength (dBm) |
| `probed_ssids` | TEXT | JSON array of probed SSIDs |
| `host_id` | INTEGER FK | Reference to hosts |
| `first_seen` | TEXT NOT NULL | First discovery timestamp |
| `last_seen` | TEXT NOT NULL | Last activity timestamp |
| `scan_session_id` | INTEGER FK | Reference to scan_sessions |

**Unique constraint:** `(mac)`

### rf_signals

Captures from PortaPack and Flipper Zero Sub-GHz.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-incrementing signal ID |
| `frequency_hz` | INTEGER NOT NULL | Frequency in Hz |
| `modulation` | TEXT | Modulation type (ASK, FSK, etc.) |
| `protocol` | TEXT | Decoded protocol name |
| `data_hex` | TEXT | Raw signal data in hex |
| `signal_strength` | INTEGER | Signal strength |
| `source_device` | TEXT | Device that captured the signal |
| `capture_file` | TEXT | Path to capture file |
| `decoded_text` | TEXT | Human-readable decoded content |
| `first_seen` | TEXT NOT NULL | First capture timestamp |
| `last_seen` | TEXT NOT NULL | Last capture timestamp |
| `scan_session_id` | INTEGER FK | Reference to scan_sessions |
| `notes` | TEXT | Free-form notes |

**Indexes:** `frequency_hz`, `protocol`

### ble_devices

BLE devices discovered by Flipper Zero or Marauder.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-incrementing device ID |
| `mac` | TEXT NOT NULL | BLE MAC address |
| `name` | TEXT | Advertised device name |
| `address_type` | TEXT | Address type (default `public`) |
| `rssi` | INTEGER | Signal strength (dBm) |
| `services` | TEXT | JSON array of advertised services |
| `manufacturer_data` | TEXT | Manufacturer-specific data |
| `host_id` | INTEGER FK | Reference to hosts |
| `first_seen` | TEXT NOT NULL | First discovery timestamp |
| `last_seen` | TEXT NOT NULL | Last discovery timestamp |
| `scan_session_id` | INTEGER FK | Reference to scan_sessions |

**Unique constraint:** `(mac)`

### rfid_nfc_tags

Tags read by Flipper Zero.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-incrementing tag ID |
| `tag_type` | TEXT NOT NULL | Tag type (e.g. `EM4100`, `MIFARE Classic`, `NTAG215`) |
| `uid` | TEXT NOT NULL | Tag UID |
| `protocol` | TEXT | Protocol details |
| `atqa` | TEXT | NFC ATQA value |
| `sak` | TEXT | NFC SAK value |
| `data_hex` | TEXT | Raw tag data in hex |
| `label` | TEXT | Human-readable label |
| `first_seen` | TEXT NOT NULL | First read timestamp |
| `last_seen` | TEXT NOT NULL | Last read timestamp |
| `scan_session_id` | INTEGER FK | Reference to scan_sessions |
| `notes` | TEXT | Free-form notes |

**Unique constraint:** `(tag_type, uid)`

### credentials

Harvested credentials from any source.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-incrementing credential ID |
| `username` | TEXT | Username |
| `password` | TEXT | Password or hash value |
| `hash_type` | TEXT | Hash algorithm (e.g. `WPA-PMKID`, `NTLM`, `bcrypt`) |
| `cracked` | INTEGER | Whether the hash was cracked (default 0) |
| `source` | TEXT | Where the credential was captured from |
| `host_id` | INTEGER FK | Reference to hosts |
| `wifi_network_id` | INTEGER FK | Reference to wifi_networks |
| `first_seen` | TEXT NOT NULL | Capture timestamp |
| `scan_session_id` | INTEGER FK | Reference to scan_sessions |
| `notes` | TEXT | Free-form notes |
