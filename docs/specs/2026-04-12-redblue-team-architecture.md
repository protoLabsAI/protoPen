# protoPen Red/Blue Team Architecture

> **Date:** 2026-04-12
> **Status:** Draft
> **Author:** protoPen team

---

## Executive Summary

Expand protoPen from a passive recon agent into an autonomous red team / blue team platform that learns from every engagement. Five phases: (1) enforcement & safety foundation, (2) network red team, (3) web/API red team, (4) blue team, (5) new hardware. Core principles: enforcement-first, pluggable execution backends, playbook-driven autonomy with tiered approval, configurable kill chain depth, and organic knowledge growth.

---

## Core Architectural Principles

### 1. Enforcement-First

Every capability addition is gated by safety infrastructure. No new attack tool ships without hard middleware enforcement of engagement mode, scope validation, and kill chain ceiling. The agent graph middleware intercepts every tool call — not relying on prompt instructions.

### 2. Organic Knowledge Growth

The agent learns from every engagement and grows its knowledge base:

- **Engagement memory**: After each engagement, findings are distilled into reusable intelligence — "this Samsung TV model has these attack surfaces", "CORS * on this service version is exploitable via X"
- **Technique evolution**: When an attack path succeeds, the agent records the chain (tools, params, order) as a learned technique. When it fails, it records why and what it tried.
- **Stale knowledge detection**: Findings have timestamps. On re-engagement with a known target, the agent diffs current state vs stored knowledge and flags what changed (patched vulns, new services, removed hosts).
- **CVE correlation**: When a vulnerability is discovered on a target, the agent cross-references the security_memory CVE database for known exploits, then records whether the exploit actually worked against this specific target/version.
- **Playbook refinement**: Playbooks aren't static YAML. The agent can propose playbook modifications based on what it learned — "step 3 of the Apache playbook should try nuclei template X before sqlmap because it's faster and catches 80% of cases."
- **Knowledge decay**: Findings older than a configurable TTL (default 90 days) are flagged for re-validation. The agent can autonomously re-scan known targets in passive mode to refresh stale data.

### 3. Pluggable Execution Backends

Tool execution is abstracted behind a backend interface:

- `local` — subprocess on the Deck (default)
- `ssh` — execute on a remote attack box via SSH
- `rpc` — Metasploit RPC, or other API-based tool backends
- `container` — Docker container execution for isolated/heavy tools

Each tool wrapper declares its preferred backend. The execution router resolves the backend at runtime from engagement config.

### 4. Playbook-Driven Autonomy with Tiered Approval

- **Known playbooks** execute autonomously within engagement constraints
- **Novel attack paths** (no matching playbook) require Discord approval
- **High-risk actions** (defined per tool: data exfil, persistence, credential dumping) always require Discord approval regardless of playbook
- Approval requests include: what the agent wants to do, why (evidence from recon), expected impact, and rollback plan

### 5. Configurable Kill Chain Depth

Engagement config includes `max_phase`:

```
recon → enumeration → exploitation → post_exploitation → lateral_movement → persistence → exfil
```

The agent cannot initiate actions beyond the ceiling. Phase transitions are logged and auditable.

---

## Phase 1: Enforcement & Safety Foundation

### 1.1 Hard Middleware Enforcement

Wire `check_engagement_mode()` into the agent graph as actual middleware:

- Intercept every tool call before execution
- Check: (a) engagement is active, (b) tool's risk level ≤ current mode, (c) target is in scope, (d) action is within kill chain ceiling
- Reject unauthorized calls with structured error explaining why
- Log all rejections to audit trail

Implementation: Add an `EnforcementMiddleware` class to `graph/middleware/` that wraps all tool execution. The existing `AuditMiddleware` stays for logging but enforcement is a separate concern.

### 1.2 Scope Enforcement

- Parse engagement scope (CIDR, domain list, URL list) into a `ScopeValidator`
- Before any network tool call, extract target from args (IP, hostname, URL) and validate against scope
- Support scope types: `cidr` (IP ranges), `domain` (wildcard domains), `url` (specific endpoints), `any` (unrestricted — for lab use)
- Out-of-scope calls are hard-blocked, not warnings

### 1.3 Kill Chain Ceiling

- Add `max_phase` field to `engagement-config.json` and engagement start action
- Define phase enum: `RECON=0`, `ENUMERATION=1`, `EXPLOITATION=2`, `POST_EXPLOITATION=3`, `LATERAL_MOVEMENT=4`, `PERSISTENCE=5`, `EXFIL=6`
- Each tool action is tagged with its minimum phase
- Middleware enforces: `action.phase ≤ engagement.max_phase`

### 1.4 shell_exec Lockdown

- Flip from "block known bad, allow unknown" to "allow known good, block unknown"
- Unrecognized commands are rejected by default
- Add `--force` flag that still requires engagement mode REDTEAM

### 1.5 Audit Trail Upgrade

- Move engagement history from file-based JSON to SQLite (`engagements.db`)
- Tables: `engagements`, `findings`, `tool_calls`, `approvals`, `phase_transitions`, `knowledge_events`
- Queryable: "show me all high-severity findings from the last 30 days", "what tools were used against 192.168.4.29"
- Retention: permanent (engagement data is institutional knowledge)

### 1.6 Rate Limiting

- Per-engagement rate limits on attack tools (configurable in engagement config)
- Defaults: max 10 deauths/hour, max 100 login attempts/hour (hydra/medusa), max 5 exploit attempts per target/hour
- Agent gets structured feedback when rate-limited: "Rate limit reached for deauth. 47 minutes until next allowed attempt."

---

## Phase 2: Network Red Team Domain

### 2.1 Domain Structure

Network red teaming organized by kill chain phase:

#### Reconnaissance

New tool wrappers:

- `dns_enum` — dig, nslookup, zone transfers, reverse lookups
- `subdomain_discovery` — subfinder, amass (passive mode)
- `osint_recon` — theHarvester (emails, subdomains, IPs from public sources)
- Enhance existing `nmap_scan` with OS detection scripts, UDP scanning

All recon output auto-ingests into TargetStore.

#### Enumeration

New tool wrappers:

- `web_enum` — enhanced gobuster/ffuf with wordlist selection, recursive mode
- `service_enum` — enum4linux (SMB), rpcclient, smbclient for Windows/Samba targets
- `ssl_audit` — testssl.sh for TLS configuration analysis
- `api_enum` — OpenAPI/Swagger schema discovery, endpoint enumeration

#### Vulnerability Assessment

New tool wrappers:

- `vuln_scan` — nuclei template scanning (community + custom templates)
- `sql_test` — sqlmap integration for SQL injection detection
- `web_vuln` — enhanced nikto, plus custom checks for CORS, SSRF, open redirects
- `cve_match` — cross-reference discovered service versions against security_memory CVE data

This is where organic knowledge kicks in: when a vuln is found, the agent checks its knowledge base for prior encounters with this CVE/service combo and records new findings.

#### Exploitation

New tool wrappers:

- `msf_exploit` — Metasploit RPC client for exploit selection and execution
- `credential_attack` — hydra/medusa for brute-force, crackmapexec for spray
- `hashcat_enhanced` — expanded hashcat wrapper with rule-based attacks, not just dictionary

Execution backend: Metasploit runs via RPC (local or remote). Credential attacks run local or SSH remote.

#### Post-Exploitation

New tool wrappers:

- `session_manager` — Metasploit session interaction (if msf is backend)
- `data_gather` — automated collection of interesting files, configs, credentials from compromised hosts
- `priv_esc` — linpeas/winpeas execution and output parsing

#### Lateral Movement

New tool wrappers:

- `pivot_planner` — analyze network topology from compromised position, suggest next targets
- `relay_attack` — responder, impacket relay tools
- `pass_the_hash` — crackmapexec PTH, impacket PSExec/WMIExec

### 2.2 Attack Chain Planner (New Subagent)

A new `chain_planner` subagent that:

1. Takes recon output + target profile + kill chain ceiling as input
2. Queries knowledge base for prior engagements against similar targets
3. Matches against available playbooks
4. Produces a phased attack plan with:
   - Ordered steps per phase
   - Expected tools and parameters
   - Success criteria per step
   - Fallback paths if a step fails
   - Approval gates (which steps need Discord approval)
5. The plan is presented to the user (via chat or Discord) before execution begins

### 2.3 Playbook System

Playbooks are YAML files in `config/playbooks/`:

```yaml
name: web-server-apache-php
target_profile:
  services: [http, https]
  software: [apache, php]
phases:
  recon:
    - action: nmap_scan
      args: { ports: "80,443,8080,8443" }
    - action: ssl_audit
      args: {}
  enumeration:
    - action: web_enum
      args: { wordlist: "common.txt", recursive: true }
    - action: nuclei
      args: { templates: "http/technologies/apache" }
  exploitation:
    - action: sql_test
      args: { forms: true, level: 3 }
      approval: auto  # known playbook step
    - action: msf_exploit
      args: { search: "apache php" }
      approval: discord  # always requires approval
success_criteria:
  - "at least one vulnerability confirmed exploitable"
learned_from:
  - engagement_id: "abc-123"
    note: "nuclei before sqlmap catches 80% of cases faster"
```

Playbooks can be:

- **Shipped** — bundled with protoPen for common target profiles
- **Learned** — generated from successful engagement chains
- **Proposed** — agent suggests based on experience, user approves before promotion

### 2.4 Target Profiles

Extend the TargetStore with a `target_profiles` table:

- Links a host to a profile template (web server, IoT device, router, NAS, etc.)
- Profiles aggregate findings, known vulns, attack history
- Profiles enable playbook matching: "this host matches web-server-apache-php profile"

---

## Phase 3: Web/API Red Team Domain

### 3.1 Web Application Testing

- `sqlmap` integration with form detection, cookie handling, WAF detection
- `nuclei` custom templates for OWASP Top 10
- CORS validator (already found issues — make it a structured tool)
- SSRF detector with callback server
- JWT analysis tool (decode, check algorithm confusion, key brute)

### 3.2 API Testing

- OpenAPI/Swagger schema parsing → automatic endpoint fuzzing
- Authentication testing (token manipulation, privilege escalation checks)
- Rate limit testing
- BOLA/IDOR detection patterns
- GraphQL introspection and query fuzzing

### 3.3 Web Knowledge Integration

- Web findings correlate with CVE database
- Agent learns which WAF signatures block which payloads
- Successful bypass techniques are stored as reusable knowledge

---

## Phase 4: Blue Team Domain

### 4.1 Defensive Scanning

- CIS benchmark validation scripts (per OS/service)
- Configuration audit tools (check SSH config, TLS settings, firewall rules)
- Patch level assessment (compare installed versions vs known CVEs)
- Open port audit against expected baselines

### 4.2 Network Monitoring

- Passive traffic analysis baselines (what's normal on this network)
- Anomaly detection: new hosts, new services, unexpected protocols
- DNS monitoring: detect DNS exfiltration, tunneling, suspicious queries

### 4.3 Hardening Playbooks

- Per-service hardening checklists the agent validates
- "Is this SSH server configured according to our baseline?"
- Remediation recommendations with specific config changes

### 4.4 Incident Response

- Log correlation across multiple sources
- IOC matching against threat intel from security_memory
- Timeline reconstruction from engagement/audit data
- Containment recommendations based on attack path analysis

### 4.5 Purple Team Mode

- Run a red team attack → immediately run blue team detection
- Validate: did monitoring detect the attack? Were alerts generated?
- Measure detection gap: time between attack and detection
- Generate purple team reports: attack coverage matrix

---

## Phase 5: New Hardware (Future)

Expansion to additional hardware after exhausting software capabilities. Specific hardware TBD based on gaps identified in Phases 1-4.

---

## Data Architecture

### Knowledge Growth Model

```
Engagement → Findings → Intelligence
                ↓
        Technique Library (what worked, what didn't)
                ↓
        Playbook Evolution (refined attack sequences)
                ↓
        Target Profiles (accumulated per-target knowledge)
                ↓
        Stale Knowledge Detection (TTL-based re-validation)
```

### New Tables (engagements.db)

| Table | Purpose |
|---|---|
| `engagement_history` | Full engagement records with phase, mode, scope, duration, outcome |
| `tool_calls` | Every tool invocation with args, result, duration, phase |
| `approval_log` | Discord approval requests and responses |
| `phase_transitions` | When the agent moved between kill chain phases |
| `techniques` | Learned attack techniques (chain of tool calls that succeeded/failed) |
| `playbook_proposals` | Agent-suggested playbook modifications awaiting approval |

### Knowledge Store Extensions (security.db)

| Table | Purpose |
|---|---|
| `target_profiles` | Aggregated per-target intelligence |
| `attack_history` | Per-target attack attempts and outcomes |
| `technique_effectiveness` | Success rates per technique per target profile type |
| `knowledge_freshness` | TTL tracking for stale knowledge detection |

---

## Approval Flow

```
Agent wants to perform action
    ↓
EnforcementMiddleware checks:
  1. Engagement active? → NO → block
  2. Mode allows risk level? → NO → block
  3. Target in scope? → NO → block
  4. Within kill chain ceiling? → NO → block
  5. Rate limit OK? → NO → throttle
    ↓
Playbook match?
  YES → approval: auto → execute
  YES → approval: discord → post to Discord, wait
  NO → novel action → post to Discord, wait
    ↓
Execute tool → capture result
    ↓
Auto-ingest into TargetStore
Log to audit trail
Update knowledge base (technique, target profile)
```

---

## Discord Integration

### Approval Requests

```
🔴 APPROVAL REQUIRED — protoPen

Engagement: LAN Recon Sweep
Target: 192.168.4.29 (Samsung Smart TV)
Phase: EXPLOITATION
Action: msf_exploit → search "samsung tizen"

Evidence:
- 11 open ports discovered (recon phase)
- Wildcard CORS on :8080 (HIGH)
- UPnP services on 4 ports (MEDIUM)

Risk: Exploitation attempt against consumer IoT device
Rollback: No persistent changes expected

React ✅ to approve, ❌ to deny
```

### Knowledge Updates

```
📚 KNOWLEDGE UPDATE — protoPen

New technique learned from "LAN Recon Sweep":
Samsung Tizen TV (model: 2022+)
→ UPnP ports expose device info without auth
→ REST API on :8001 returns 401 but leaks server version in headers
→ CORS * on :8080 allows cross-origin API access

Added to target profile: samsung-tizen-tv
Playbook proposal: iot-samsung-tv (3 new steps)
```
