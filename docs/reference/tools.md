# Tools

Complete reference for all agent tools and their actions. Tools are grouped by the hardware or domain they control.

## portapack

Controls a PortaPack H4M (HackRF One + Mayhem firmware) via USB serial. Frequency range: 1 MHz -- 6 GHz.

| Action | Description | Key Parameters |
|---|---|---|
| `list_apps` | List available Mayhem apps on the device | -- |
| `start_app` | Start an app by short name | `app_name` |
| `set_frequency` | Tune to a frequency | `frequency_hz` |
| `radio_info` | Get current radio status (frequency, mode, modulation) | -- |
| `read_screen` | Read all on-screen text (accessibility bridge) | -- |
| `screenshot` | Capture the current screen frame | -- |
| `tap` | Tap the touchscreen at coordinates | `x` (0--240), `y` (0--320) |
| `press_button` | Press a hardware button | `button` (1=Right, 2=Left, 3=Down, 4=Up, 5=Select, 7=RotaryL, 8=RotaryR) |
| `system_info` | Get device system information | -- |
| `send_pocsag` | Transmit a POCSAG pager message | `address`, `message` |
| `send_command` | Send a raw serial command to the device | `command` |
| `file_list` | List files on the SD card | `path` |
| `reboot` | Reboot the device | -- |
| `inject_gps` | Inject a GPS position | `lat`, `lon`, `alt`, `speed` |
| `inject_orientation` | Inject a compass orientation | `degrees` |

---

## flipper

Serial bridge for the Flipper Zero multi-tool. Supports Sub-GHz, NFC, RFID, IR, Bluetooth, storage, and GPIO.

| Action | Description | Key Parameters |
|---|---|---|
| `subghz_rx` | Receive/listen on a Sub-GHz frequency | `freq`, `device` |
| `subghz_tx` | Transmit a Sub-GHz key | `freq`, `key_hex`, `te`, `repeat` |
| `subghz_tx_from_file` | Transmit a captured Sub-GHz signal from file | `path` |
| `subghz_decode_raw` | Decode a raw Sub-GHz capture file | `path` |
| `nfc_detect` | Detect and read an NFC tag | -- |
| `nfc_field` | Toggle the NFC field on/off | `on` |
| `rfid_read` | Read an RFID tag | -- |
| `rfid_write` | Write data to an RFID tag | `protocol`, `data_hex` |
| `rfid_emulate` | Emulate an RFID tag | `protocol`, `data_hex` |
| `ir_rx` | Receive an IR signal | -- |
| `ir_tx` | Transmit an IR command | `protocol`, `address`, `command` |
| `ir_tx_raw` | Transmit a raw IR signal | `raw_args` |
| `ir_brute` | Brute-force IR signals from a universal remote | `remote_name`, `signal_name` |
| `bt_info` | Get Bluetooth adapter information | -- |
| `storage_list` | List files/directories on the Flipper SD | `path` |
| `storage_read` | Read a file from the Flipper SD | `path` |
| `storage_stat` | Get file/directory stats | `path` |
| `storage_mkdir` | Create a directory on the Flipper SD | `path` |
| `storage_md5` | Get MD5 hash of a file on the Flipper SD | `path` |
| `gpio_set` | Set a GPIO pin value | `pin`, `value` (0 or 1) |
| `gpio_read` | Read a GPIO pin value | `pin` |
| `device_info` | Get Flipper device information (firmware, HW revision) | -- |
| `power_info` | Get battery and power status | -- |
| `send_command` | Send a raw CLI command | `cmd` |

---

## marauder

Serial bridge for the ESP32 WiFi Marauder firmware. WiFi scanning, attacks, sniffing, BLE, evil portal, and SSID management.

| Action | Description | Key Parameters |
|---|---|---|
| `scan_aps` | Scan for WiFi access points | -- |
| `scan_stations` | Scan for WiFi client stations | -- |
| `stop` | Stop the current operation | -- |
| `list_results` | List scan results | `kind` (`aps`, `stations`, `ssids`) |
| `select_targets` | Select specific targets by index | `indices` |
| `select_all` | Select all discovered targets | -- |
| `set_channel` | Lock to a specific WiFi channel | `ch` |
| `clear_list` | Clear the target/results list | -- |
| `deauth` | Send deauthentication frames to selected targets | -- |
| `beacon_spam` | Broadcast fake beacon frames | -- |
| `probe_flood` | Flood probe requests | -- |
| `rickroll` | Beacon spam with rickroll SSIDs | -- |
| `sniff_pmkid` | Capture PMKID hashes for offline cracking | `deauth` (boolean) |
| `sniff_deauth` | Sniff deauthentication frames | -- |
| `sniff_beacon` | Sniff beacon frames | -- |
| `sniff_raw` | Raw 802.11 packet sniffing | -- |
| `bt_spam_all` | Broadcast BLE spam across all protocols | -- |
| `sour_apple` | Apple-specific BLE denial-of-service | -- |
| `swift_pair` | Windows Swift Pair BLE spam | -- |
| `samsung_ble_spam` | Samsung-specific BLE spam | -- |
| `evil_portal` | Start a captive portal attack | `html_path` |
| `karma` | Start a karma AP (responds to all probe requests) | -- |
| `ssid_add` | Add an SSID to the broadcast list | `name` |
| `ssid_generate` | Auto-generate random SSIDs | `count` |
| `info` | Get Marauder device/firmware info | -- |
| `send_command` | Send a raw CLI command | `cmd` |

---

## blackarch

Curated wrappers for BlackArch pen testing tools installed on the system, plus a guarded shell fallback.

| Action | Description | Key Parameters |
|---|---|---|
| `nmap_scan` | Network host/service discovery scan | `target`, `ports`, `timeout` |
| `nmap_vuln_scan` | Nmap with vulnerability detection scripts | `target`, `timeout` |
| `airmon_start` | Put WiFi interface into monitor mode | `interface` |
| `airmon_stop` | Take WiFi interface out of monitor mode | `interface` |
| `airodump_scan` | Capture WiFi traffic with airodump-ng | `interface`, `timeout` |
| `bettercap_recon` | Network reconnaissance with bettercap | `target`, `interface` |
| `hashcat_crack` | Crack hashes with hashcat | `hash_file`, `hash_type`, `wordlist` |
| `nikto_scan` | Web server vulnerability scan | `url`, `timeout` |
| `gobuster_scan` | Directory/file brute-force on web servers | `url`, `wordlist` |
| `tshark_capture` | Capture network packets with tshark | `interface`, `count`, `output_file` |
| `shell_exec` | Execute a shell command (guarded) | `command`, `timeout` |

::: warning
`shell_exec` filters commands against a blocklist (no `rm`, `shutdown`, `iptables`, etc.) and an allowlist of known safe tools (`nmap`, `tshark`, `curl`, `dig`, etc.). Arbitrary commands outside the allowlist are rejected.
:::

---

## device_manager

Manages USB serial connections to all attached pen testing hardware.

| Action | Description | Key Parameters |
|---|---|---|
| `connect` | Connect to a device by name | `device_name` (`portapack`, `flipper`, `marauder`, `wifi_adapter`) |
| `disconnect` | Disconnect a device | `device_name` |
| `health_check` | Run a health check on a connected device | `device_name` |
| `all_status` | Get connection status of all configured devices | -- |

---

## engagement

Mission control for pen testing operations. Manages lifecycle, mode enforcement, findings, and reports.

| Action | Description | Key Parameters |
|---|---|---|
| `start` | Start a new engagement | `name`, `scope`, `mode` |
| `end` | End the active engagement | -- |
| `set_mode` | Change the engagement mode | `mode` (`passive`, `active`, `redteam`) |
| `status` | Get current engagement status | -- |
| `log_finding` | Log a security finding | `severity`, `category`, `title`, `detail` |
| `check_permission` | Check if a tool action is permitted at the current mode | `tool_name` |
| `generate_report` | Generate a markdown report from all findings | -- |
| `list_findings` | List all findings in the current engagement | -- |

---

## target_intel

Query and manage the target intelligence database. Tracks hosts, services, WiFi, RF, BLE, RFID, and credentials across all sensor platforms.

| Action | Description | Key Parameters |
|---|---|---|
| `upsert_host` | Add or update a host | `ip`, `mac`, `hostname`, `os`, `vendor`, `device_type` |
| `query_hosts` | Search hosts by IP prefix, device type, or time | `ip_prefix`, `device_type`, `since` |
| `get_host` | Get detailed info for a host by ID | `host_id` |
| `upsert_port` | Add or update a port/service on a host | `host_id`, `port`, `protocol`, `service`, `banner` |
| `upsert_wifi_network` | Add or update a WiFi access point | `bssid`, `ssid`, `channel`, `rssi`, `encryption` |
| `upsert_wifi_station` | Add or update a WiFi client station | `mac`, `rssi` |
| `add_rf_signal` | Record an RF signal capture | `frequency_hz`, `modulation`, `protocol`, `data_hex`, `source_device` |
| `upsert_ble_device` | Add or update a BLE device | `mac`, `name`, `rssi` |
| `upsert_rfid_nfc_tag` | Add or update an RFID/NFC tag | `tag_type`, `uid`, `label` |
| `add_credential` | Record a harvested credential | `username`, `password`, `hash_type`, `source`, `host_id` |
| `start_scan` | Start a scan session for temporal tracking | `tool`, `scan_action`, `engagement` |
| `end_scan` | End a scan session | `scan_session_id` |
| `stats` | Get entity counts across all tables | -- |
| `diff` | Show new entities since a given timestamp | `since` (ISO 8601) |
