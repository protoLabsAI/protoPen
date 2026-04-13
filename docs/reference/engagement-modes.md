# Engagement Modes

protoPen enforces three engagement modes that control which tools the agent is permitted to use. Every pentest tool action has an assigned risk level, and the current mode determines the maximum risk allowed.

## Mode Definitions

| Mode | Level | Description |
|---|---|---|
| **PASSIVE** | 0 | Observation only. No transmissions, no active probing. Listen, scan, enumerate. |
| **ACTIVE** | 1 | Active probing permitted. Service scanning, PMKID capture, signal replay, RFID read. |
| **REDTEAM** | 2 | Full offensive operations. Deauth, evil portal, karma AP, BLE spam, RFID emulation. |

The mode is set per-engagement and defaults to `passive` (configurable in `engagement-config.json`).

## Risk-Gated Tool Access

Each tool action has a risk level (0, 1, or 2). A tool action is permitted only if its risk level is less than or equal to the current engagement mode level.

### Risk Level 0 (PASSIVE) -- Always Allowed

| Tool | Actions |
|---|---|
| portapack | `rf_scan`, `rf_read_screen`, `rf_radio_info`, `rf_screenshot`, `rf_capture`, `rf_set_frequency`, `rf_app_start` |
| flipper | `flip_subghz_rx`, `flip_nfc_read`, `flip_rfid_read`, `flip_ir_rx`, `flip_ble_scan`, `flip_storage_list` |
| marauder | `wifi_scan_aps`, `wifi_scan_stations` |
| blackarch | `nmap_scan`, `aircrack_monitor`, `aircrack_capture`, `bettercap_recon` |

### Risk Level 1 (ACTIVE) -- Requires Active Mode

| Tool | Actions |
|---|---|
| portapack | `rf_replay`, `rf_send_pocsag` |
| flipper | `flip_subghz_tx`, `flip_nfc_write`, `flip_rfid_write`, `flip_ir_tx` |
| marauder | `wifi_sniff_pmkid` |
| blackarch | `nmap_vuln_scan`, `aircrack_crack`, `shell_exec` |

### Risk Level 2 (REDTEAM) -- Requires Red Team Mode

| Tool | Actions |
|---|---|
| flipper | `flip_subghz_bruteforce` |
| marauder | `wifi_deauth`, `wifi_beacon_spam`, `wifi_evil_portal`, `wifi_karma` |
| blackarch | `bettercap_mitm` |

## How Enforcement Works

1. Before every tool call, the `EngagementManager.is_allowed(tool_name)` method checks the tool's risk level against the current mode.
2. If the risk level exceeds the mode, the call is **denied** and the agent receives an error message explaining what mode is required.
3. The guardrails module (`guardrails.py`) also performs pre-flight checks via `check_engagement_mode()`.
4. Subagents (Recon, Exploit, Reporter) are trained to call `engagement check_permission` before every action.

## Changing Modes

During an engagement:

```
Set the engagement mode to active
```

Or via the tool directly:

```json
{"action": "set_mode", "mode": "active"}
```

::: warning
Mode escalation (e.g. PASSIVE to REDTEAM) should only happen with explicit authorization. The agent will not auto-escalate modes -- it will report when a higher mode is needed and wait for instructions.
:::

## Alerts

When a finding with `critical` or `high` severity is logged, protoPen sends an alert to the configured Discord webhook (`alert_webhook` in `engagement-config.json`). This provides real-time notification of significant discoveries.
