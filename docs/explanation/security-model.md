# Security Model

protoPen operates hardware that can transmit RF signals, deauthenticate WiFi clients, and run exploit code. The security model ensures the agent cannot accidentally (or intentionally) exceed the authorized scope of an engagement.

## Layers of Defense

```
┌──────────────────────────────────────────┐
│          Engagement Modes                │  ← Risk-gated tool access
├──────────────────────────────────────────┤
│          Command Blocklist               │  ← Shell command filtering
├──────────────────────────────────────────┤
│          Guardrails                      │  ← Scope validation + query rewriting
├──────────────────────────────────────────┤
│          Audit Trail                     │  ← Every tool call recorded
├──────────────────────────────────────────┤
│          Docker Hardening                │  ← Container-level isolation
├──────────────────────────────────────────┤
│          Discord Alerts                  │  ← Real-time human notification
└──────────────────────────────────────────┘
```

## Engagement Modes as Risk Gates

Every pentest tool action has an assigned risk level (0, 1, or 2). The current engagement mode determines the maximum permitted risk:

| Mode | Level | Allows |
|---|---|---|
| PASSIVE | 0 | Listen, scan, enumerate. No transmission. |
| ACTIVE | 1 | Active probing, PMKID capture, signal replay, vuln scan |
| REDTEAM | 2 | Deauth, evil portal, karma AP, BLE spam, brute force |

Before executing any tool action, the `EngagementManager.is_allowed()` method checks whether the action's risk level is within the current mode. Denied actions return an error to the agent explaining what mode is needed.

The agent does not auto-escalate modes. If it needs a higher mode, it reports the requirement and waits for explicit human instruction.

See [Engagement Modes](../reference/engagement-modes.md) for the full tool-to-risk mapping.

## Command Blocklist

The `BlackArchTool` (which provides `shell_exec`) enforces two filters:

**Blocked commands** -- always rejected:

```
rm, rmdir, mkfs, dd, fdisk, parted, shutdown, reboot, poweroff, halt,
init, chmod, chown, chgrp, systemctl, service, useradd, userdel, passwd,
usermod, iptables, ip6tables, nft
```

**Safe commands** -- allowlisted for `shell_exec`:

```
nmap, tshark, tcpdump, kismet, airodump-ng, airmon-ng, nikto, gobuster,
dirb, ffuf, sqlmap, wpscan, hashcat, john, bettercap, dig, nslookup,
whois, host, ping, traceroute, mtr, curl, wget, arp-scan, netdiscover,
enum4linux, smbclient, rpcclient, hydra, medusa
```

Commands not on the allowlist are rejected. This prevents the agent from running arbitrary shell commands even if it has `shell_exec` access.

## Guardrails

The `guardrails.py` module provides three pre-flight checks:

### Scope Validation

Queries are scored for relevance to the agent's domain (security research or pen testing) on a 0-100 scale. Queries below the threshold (default: 40) are rejected. A keyword heuristic provides fast bypass for obviously relevant queries; borderline cases are checked via LLM.

### Query Rewriting

When a search returns sparse or no results, the guardrails module rewrites the query using the LLM to improve recall. Common abbreviations are expanded (e.g., "RCE" becomes "remote code execution RCE").

### Document Grading

A binary relevance check filters out irrelevant documents before they enter the knowledge store. The LLM answers "yes" or "no" based on a 500-character excerpt.

### Engagement Mode Enforcement

The `check_engagement_mode()` function validates tool calls against the current engagement mode before execution, providing a second enforcement point beyond the tool-level check.

## Audit Trail

Every tool execution is logged to `/sandbox/audit/audit.jsonl` as a JSONL entry:

```json
{
  "ts": "2026-04-12T14:30:00+00:00",
  "session_id": "abc123",
  "tool": "blackarch",
  "args": {"action": "nmap_scan", "target": "192.168.1.0/24"},
  "result_summary": "Found 12 live hosts...",
  "duration_ms": 4523,
  "success": true,
  "trace_id": "langfuse-trace-xyz"
}
```

The audit log captures:

- Timestamp, session ID, tool name, sanitized arguments
- Result summary (first 200 characters)
- Duration in milliseconds
- Success/failure status
- Langfuse trace ID for cross-referencing with the observability stack

The `/audit [n]` chat command surfaces recent entries for quick review.

## Docker Security

The standard (non-lab) container runs with defense-in-depth hardening:

| Measure | Configuration |
|---|---|
| **seccomp profile** | Custom allowlist of ~120 syscalls; all others return EPERM |
| **no-new-privileges** | Prevents privilege escalation via setuid binaries |
| **drop ALL capabilities** | Only `NET_RAW` is added back (required for nmap/aircrack) |
| **read-only root filesystem** | Container root is immutable; only tmpfs and volumes are writable |
| **tmpfs mounts** | `/tmp`, `/run`, `/sandbox`, `/home/sandbox` are ephemeral tmpfs |
| **persistent volumes** | Only knowledge DB, audit logs, papers, and cron state persist |
| **resource limits** | CPU: 4 cores, memory: 4 GB (standard) or 16 GB (lab) |
| **non-root user** | Runs as `sandbox` (UID 1001) |

The lab profile relaxes the seccomp profile (CUDA requires additional syscalls) but retains `no-new-privileges` and capability dropping.

## Discord Alerts

When the `EngagementManager` logs a finding with `critical` or `high` severity, it immediately posts to the configured Discord webhook:

```
🔴 CRITICAL — Default credentials on IoT gateway
Category: authentication
```

This provides real-time human oversight of the agent's most significant discoveries, even when no one is watching the chat UI.

::: warning
Discord alerts require `alert_webhook` to be set in `engagement-config.json`. Without it, critical findings are logged but not pushed to any notification channel.
:::
