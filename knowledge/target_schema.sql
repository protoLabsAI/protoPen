-- protoPen target intelligence schema
-- Unified multi-sensor target tracking for pentest engagements

-- Scan sessions: temporal grouping for every scan/capture operation
CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement TEXT,
    tool TEXT NOT NULL,
    action TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    raw_output TEXT,
    notes TEXT
);

-- Hosts: central entity — anything with an IP or MAC address
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    mac TEXT,
    hostname TEXT,
    os TEXT,
    vendor TEXT,
    device_type TEXT DEFAULT 'unknown',
    tags TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    scan_session_id INTEGER REFERENCES scan_sessions(id),
    notes TEXT,
    UNIQUE(ip, mac)
);

CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac);
CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen);

-- Ports: services discovered on hosts
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL DEFAULT 'open',
    service TEXT,
    banner TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    scan_session_id INTEGER REFERENCES scan_sessions(id),
    UNIQUE(host_id, port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);

-- WiFi networks: access points discovered by Marauder / aircrack / bettercap
CREATE TABLE IF NOT EXISTS wifi_networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid TEXT NOT NULL,
    ssid TEXT,
    channel INTEGER,
    rssi INTEGER,
    encryption TEXT,
    wps INTEGER DEFAULT 0,
    host_id INTEGER REFERENCES hosts(id),
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
    mac TEXT NOT NULL,
    network_id INTEGER REFERENCES wifi_networks(id),
    rssi INTEGER,
    probed_ssids TEXT,
    host_id INTEGER REFERENCES hosts(id),
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
    modulation TEXT,
    protocol TEXT,
    data_hex TEXT,
    signal_strength INTEGER,
    source_device TEXT,
    capture_file TEXT,
    decoded_text TEXT,
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
    mac TEXT NOT NULL,
    name TEXT,
    address_type TEXT DEFAULT 'public',
    rssi INTEGER,
    services TEXT,
    manufacturer_data TEXT,
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
    tag_type TEXT NOT NULL,
    uid TEXT NOT NULL,
    protocol TEXT,
    atqa TEXT,
    sak TEXT,
    data_hex TEXT,
    label TEXT,
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
    password TEXT,
    hash_type TEXT,
    cracked INTEGER DEFAULT 0,
    source TEXT,
    host_id INTEGER REFERENCES hosts(id),
    wifi_network_id INTEGER REFERENCES wifi_networks(id),
    first_seen TEXT NOT NULL,
    scan_session_id INTEGER REFERENCES scan_sessions(id),
    notes TEXT
);
