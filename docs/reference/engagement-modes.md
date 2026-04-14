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
| container_audit | `kube_bench`, `kube_bench_target`, `trivy_image`, `trivy_k8s`, `trivy_fs` |

### Risk Level 1 (ACTIVE) -- Requires Active Mode

| Tool | Actions |
|---|---|
| portapack | `rf_replay`, `rf_send_pocsag` |
| flipper | `flip_subghz_tx`, `flip_nfc_write`, `nfc_emulate`, `flip_rfid_write`, `flip_ir_tx` |
| marauder | `wifi_sniff_pmkid` |
| blackarch | `nmap_vuln_scan`, `aircrack_crack`, `shell_exec` |
| container_audit | `kube_hunter`, `kube_hunter_internal`, `deepce`, `cdk_evaluate` |
| websocket_test | `auth_bypass`, `cswsh` |

### Risk Level 2 (REDTEAM) -- Requires Red Team Mode

| Tool | Actions |
|---|---|
| flipper | `flip_subghz_bruteforce` |
| marauder | `wifi_deauth`, `wifi_beacon_spam`, `wifi_evil_portal`, `wifi_karma` |
| blackarch | `bettercap_mitm` |
| flipper | `subghz_bruteforce` |
| container_audit | `cdk_exploit` |
| websocket_test | `injection` |

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

## Reports

`engagement generate_report` produces a full markdown report from all logged findings, sorted by severity. The report is saved to `<workspace_dir>/<engagement_name>/report.md` — by default `/home/deck/engagements/<name>/report.md`.

Reports can also be published to Discord as rich embeds via `discord_feed publish` or the `/intel` chat command. See [Discord Integration](../guides/discord-integration.md) for details.

## Alerts

When a finding with `critical` or `high` severity is logged, protoPen sends an alert to the configured Discord webhook. There are two webhook paths:

- **`alert_webhook`** in `engagement-config.json` — per-engagement alerts (plain text)
- **`DISCORD_WEBHOOK_URL`** env var — used by `discord_feed publish` and `/intel` for digests and reports (rich embeds)
