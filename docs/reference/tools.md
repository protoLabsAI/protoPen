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
| `subghz_bruteforce` | Brute-force Sub-GHz codes from a .sub file | `path`, `freq`, `repeat` |
| `nfc_detect` | Detect and read an NFC tag | -- |
| `nfc_field` | Toggle the NFC field on/off | `on` |
| `nfc_emulate` | Emulate an NFC tag from a saved .nfc file | `path` |
| `rfid_read` | Read an RFID tag | -- |
| `rfid_write` | Write data to an RFID tag | `protocol`, `data_hex` |
| `rfid_emulate` | Emulate an RFID tag | `protocol`, `data_hex` |
| `ir_rx` | Receive an IR signal | -- |
| `ir_tx` | Transmit an IR command | `protocol`, `address`, `command` |
| `ir_tx_raw` | Transmit a raw IR signal | `raw_args` |
| `ir_brute` | Brute-force IR signals from a universal remote | `remote_name`, `signal_name` |
| `bt_info` | Get Bluetooth adapter information | -- |
| `ble_scan` | Scan for nearby BLE peripherals | `timeout` (seconds, default 10) |
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
| `bettercap_mitm` | ARP spoof MITM with network sniffing | `target`, `interface`, `timeout` |
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
| `generate_report` | Generate a markdown report from all findings. Saved to `<workspace_dir>/<engagement_name>/report.md` (default workspace: `/home/deck/engagements/`). | -- |
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

---

## discord_feed

Discord channel scanning and webhook publishing. Reads channel history via the Discord Bot API and publishes content as rich embeds via webhook.

| Action | Description | Key Parameters |
|---|---|---|
| `publish` | Publish content as rich Discord embeds via `DISCORD_WEBHOOK_URL`. Auto-chunks content exceeding the 4096-char embed limit. | `content`, `title` |
| `share` | Share a finding to the collaboration channel via the Discord Bot API. | `content`, `title` |
| `scan` | Extract and classify URLs from channel messages. | `channel_id` |
| `history` | Retrieve raw message history from a channel. | `channel_id`, `limit` |
| `channels` | List channels in a Discord guild. | `guild_id` |
| `digest` | Generate a structured link digest from channel history. | `channel_id` |

::: tip
The `publish` action uses `DISCORD_WEBHOOK_URL` (no channel ID needed). The `scan`, `history`, `channels`, and `digest` actions require `DISCORD_BOT_TOKEN` and a `channel_id`.
:::

---

## container_audit

Container & Kubernetes security auditing — kube-hunter cluster scanning, kube-bench CIS benchmarks, deepce escape detection, CDK exploitation toolkit, Trivy vulnerability scanning.

| Action | Description | Key Parameters |
|---|---|---|
| `kube_hunter` | Scan K8s cluster for security weaknesses (remote) | `target` |
| `kube_hunter_internal` | In-cluster kube-hunter scan (run from inside a pod) | -- |
| `kube_bench` | Run CIS Kubernetes Benchmark checks on local node | -- |
| `kube_bench_target` | CIS benchmark for specific K8s distro | `benchmark` (e.g. eks-1.1.0, gke-1.2.0) |
| `deepce` | Detect container escape vectors from inside a container | -- |
| `cdk_evaluate` | Evaluate container for exploitation opportunities (CDK) | -- |
| `cdk_exploit` | Run a specific CDK exploit by name | `exploit_name` (e.g. mount-cgroup, service-account) |
| `trivy_image` | Scan container image for known CVEs | `image`, `severity` (default: HIGH,CRITICAL) |
| `trivy_k8s` | Scan K8s cluster resources for misconfigs and CVEs | `target` |
| `trivy_fs` | Scan filesystem/project for dependency vulnerabilities | `path`, `severity` |

---

## websocket_test

WebSocket security testing — authentication bypass, Cross-Site WebSocket Hijacking (CSWSH), and message injection.

| Action | Description | Key Parameters |
|---|---|---|
| `auth_bypass` | Test WebSocket endpoint for authentication bypass | `url`, `origin`, `auth_token` |
| `cswsh` | Test for Cross-Site WebSocket Hijacking via Origin validation | `url`, `origin` |
| `injection` | Test WebSocket messages for injection vulnerabilities | `url`, `origin`, `categories` (sqli, xss, command_injection, path_traversal) |

---

## iot_audit

IoT device security assessment — nmap IoT sweep, service fingerprinting, Telnet/HTTP admin checks, MQTT broker testing, SNMP enumeration, RTSP stream discovery, firmware version exposure, and default credential spraying.

| Action | Description | Key Parameters |
|---|---|---|
| `device_discovery` | nmap IoT port sweep across a CIDR — identifies cameras, routers, NAS, smart home hubs | `target` (CIDR) |
| `fingerprint` | Deep OS + service version + banner fingerprint on a single host | `target` |
| `telnet_check` | Check for open Telnet on port 23 and 2323 (common IoT backdoor) | `target` |
| `http_admin_check` | Enumerate HTTP admin UIs on common IoT ports and test default accounts | `target` |
| `mqtt_audit` | Test MQTT broker for anonymous access via `$SYS` topic subscription | `target` |
| `snmp_audit` | Probe SNMP with default community strings using onesixtyone | `target` |
| `rtsp_discover` | Find RTSP camera streams and check for auth requirement | `target` |
| `firmware_exposure` | Banner-grab common ports for firmware and version strings | `target` |
| `default_creds` | Credential spray using common IoT defaults (hydra) | `target`, `service` |
| `full_iot_audit` | Run all checks in sequence against a target | `target` |

---

## ad_attack

Active Directory attack chain — BloodHound graph collection, Kerberoasting, AS-REP roasting, ADCS certificate abuse (Certipy ESC1–ESC8), LDAP enumeration, and domain secrets dumping. Requires `REDTEAM` mode for exploitation steps.

| Action | Description | Key Parameters |
|---|---|---|
| `bloodhound_collect` | Collect all AD objects and relationships for BloodHound ingestion | `target`, `domain`, `username`, `password` |
| `bloodhound_edges` | Focused collection of ACL relationships and domain trust edges | `target`, `domain`, `username`, `password` |
| `certipy_find` | Enumerate all ADCS certificate templates across all CAs | `target`, `domain`, `username`, `password` |
| `certipy_vuln` | Filter templates vulnerable to ESC1–ESC8 privilege escalation | `target`, `domain`, `username`, `password` |
| `certipy_req` | Request a certificate from a vulnerable template (ESC1 exploit) | `target`, `domain`, `username`, `password`, `ca_name`, `template` |
| `enum4linux_ng` | SMB/LDAP/RPC deep enumeration — users, groups, shares, password policy | `target`, `username`, `password`, `domain` |
| `ldapsearch` | LDAP query for AD objects (users, computers, groups) | `target`, `domain`, `username`, `password`, `base_dn`, `filter` |
| `kerberoast` | Request TGS tickets for SPNs — crack offline with hashcat `-m 13100` | `target`, `domain`, `username`, `password` |
| `asreproast` | Extract AS-REP hashes for accounts without preauth — crack with hashcat `-m 18200` | `target`, `domain`, `wordlist` |
| `secretsdump` | Dump NTDS.dit, SAM, and LSA secrets from the domain controller | `target`, `domain`, `username`, `password` |

---

## grpc_audit

gRPC security testing — server reflection enumeration, service/method description, auth testing, TLS enforcement, protobuf fuzzing, and port scanning.

| Action | Description | Key Parameters |
|---|---|---|
| `grpc_reflection` | List all services via gRPC server reflection | `target` (host:port) |
| `grpc_describe` | Describe service methods, request/response message shapes | `target`, `service` |
| `grpc_call` | Call a gRPC method with a data payload | `target`, `method`, `data` |
| `grpc_fuzz` | Fuzz gRPC service methods with random/malformed inputs | `target`, `service`, `count` |
| `grpc_auth_test` | Test gRPC method with and without an Authorization header | `target`, `method`, `auth_header` |
| `grpc_tls_check` | Verify the endpoint requires TLS | `target` |
| `grpc_web_test` | Test gRPC-Web endpoint with proto definitions | `target` |
| `protoscan` | Scan for exposed protobuf/gRPC endpoints across common ports | `target` |

---

## graphql_test

GraphQL security testing — introspection, depth limit DoS, batch query amplification, and field suggestion leakage.

| Action | Description | Key Parameters |
|---|---|---|
| `gql_introspect` | Test if introspection is enabled and extract the full schema | `url`, `headers` |
| `gql_depth_test` | Find server's depth limit via incrementally deeper nested queries | `url`, `headers` |
| `gql_batch` | Test batch query support — amplifies brute force and bypasses rate limiting | `url`, `headers` |
| `gql_field_suggest` | Probe for field name leakage via typo-triggered suggestion responses | `url`, `headers` |

---

## jwt_tool

JWT analysis — decode, algorithm bypass testing, HMAC secret brute-force, and claim tampering.

| Action | Description | Key Parameters |
|---|---|---|
| `jwt_decode` | Decode a JWT and display header, payload, signature; flags weak alg/claims | `token` |
| `jwt_alg_none` | Generate algorithm=none bypass variants for manual submission | `token` |
| `jwt_crack` | Brute-force HMAC secret (HS256/384/512) with a wordlist | `token`, `wordlist` |
| `jwt_tamper` | Modify JWT claims and re-sign for privilege escalation testing | `token`, `claims` |

---

## ssrf_detect

SSRF detection — payload injection into URL parameters, cloud metadata endpoint probing, and blind callback server.

| Action | Description | Key Parameters |
|---|---|---|
| `ssrf_basic` | Inject standard SSRF payloads (127.0.0.1, IPv6, etc.) into a URL parameter | `url`, `inject_param` |
| `ssrf_cloud_meta` | Probe cloud metadata endpoints (AWS/GCP/Azure/DO) directly | — |
| `ssrf_callback` | Blind SSRF detection via local callback HTTP server | `url`, `inject_param`, `callback_host`, `callback_port`, `wait_seconds` |
| `ssrf_generate_payloads` | Generate SSRF bypass payload list for manual testing | — |

---

## rate_limit

Rate limit testing — threshold detection, IP header spoofing bypass, and URL path manipulation bypass.

| Action | Description | Key Parameters |
|---|---|---|
| `rate_detect` | Send sequential requests and track HTTP 429 / Retry-After responses | `url`, `headers`, `count` |
| `rate_bypass_headers` | Test bypass via IP spoofing headers (X-Forwarded-For, X-Real-IP, etc.) | `url`, `headers`, `spoof_ip` |
| `rate_bypass_path` | Test bypass via URL normalization tricks (trailing slash, dot, double-slash) | `url`, `headers` |

---

## priv_esc

Linux privilege escalation enumeration — linpeas, sudo audit, SUID binary discovery, and kernel exploit suggestions.

| Action | Description | Key Parameters |
|---|---|---|
| `linpeas` | Comprehensive Linux privesc enumeration (crons, writable paths, capabilities, credentials) | — |
| `sudo_check` | List sudo privileges for the current user | — |
| `suid_find` | Find setuid binaries — results are GTFOBins-searchable | — |
| `kernel_exploits` | Cross-reference kernel version against known exploits | — |

---

## persistence

Persistence mechanism testing — planting and enumerating SSH keys, cron jobs, and systemd services.

| Action | Description | Key Parameters |
|---|---|---|
| `add_ssh_key` | Add attacker public key to `~/.ssh/authorized_keys` | `pubkey` |
| `add_cron` | Add a cron job for persistence | `cron_entry` |
| `check_persistence` | Enumerate current cron jobs, authorized_keys, and enabled systemd services | — |

---

## lateral_move

Lateral movement — impacket psexec/wmiexec, evil-winrm, pass-the-hash, and SSH SOCKS pivot.

| Action | Description | Key Parameters |
|---|---|---|
| `psexec` | Remote shell via SMB named pipes (impacket) | `target`, `domain`, `username`, `password` |
| `wmiexec` | WMI execution via impacket | `target`, `domain`, `username`, `password` |
| `evil_winrm` | Evil-WinRM shell for Windows Remote Management | `target`, `username`, `password` |
| `pth_winrm` | Pass-the-hash authentication via evil-winrm | `target`, `username`, `hash` |
| `ssh_pivot` | Establish SOCKS5 proxy through a compromised host | `target`, `username`, `socks_port` |

---

## data_exfil

Evidence collection — pull files from compromised hosts via SCP, SMB, or HTTP.

| Action | Description | Key Parameters |
|---|---|---|
| `scp_download` | Download file from compromised host via SCP | `target`, `username`, `remote_path`, `local_path` |
| `smb_download` | Download file from an SMB share | `target`, `share`, `remote_path`, `local_path` |
| `http_exfil` | Download file via HTTP/HTTPS | `url`, `local_path` |

---

## spa_test

Single-Page Application security — client-side route guard bypass, state store inspection, postMessage scanning, token leakage, DOM XSS, and JavaScript source map exposure.

| Action | Description | Key Parameters |
|---|---|---|
| `route_bypass` | Test SPA client-side route guard bypass (access protected routes unauthenticated) | `target`, `routes_file` |
| `state_inspect` | Inspect client-side state stores (Redux, Vuex, etc.) for sensitive data | `target`, `store_type` |
| `postmessage_scan` | Scan for insecure `postMessage` handlers | `target` |
| `token_leakage_audit` | Audit for token leakage in localStorage and URL fragments | `target` |
| `dom_xss_scan` | Scan for DOM-based cross-site scripting vulnerabilities | `target` |
| `js_source_map_check` | Check for exposed JavaScript source maps (`.map` files leak original source) | `target` |
