# Blue Team / Defensive Methodology Skill

Loaded when defensive assessment or incident response is needed. Defines phase-by-phase methodology for blue team operations.

---

## Phase 1: Defensive Assessment

**Goal:** Establish security baseline of target environment.

### Workflow
1. Run CIS benchmarks: `cis_audit ssh_audit`, `cis_audit tls_audit`, `cis_audit firewall_audit`
2. Validate service hardening: `hardening_check ssh_harden`, `hardening_check nginx_harden`, etc.
3. Check patch levels: `cis_audit patch_check`
4. Baseline open ports: `cis_audit port_baseline` with expected ports list
5. Prioritize findings by severity (critical → high → medium → low)

### Output
```
## Defensive Assessment: {target}

CIS Benchmarks:  SSH {pass}/{total} | TLS {pass}/{total} | Firewall {pass}/{total}
Hardening:       {service}: {pass}/{total}
Patch Status:    {count} pending ({severity})
Port Baseline:   {unexpected_count} unexpected ports

Remediation Priorities:
1. {critical_fix}
2. {high_fix}
3. {medium_fix}
```

---

## Phase 2: Network Monitoring

**Goal:** Establish traffic baselines and detect anomalies.

### Workflow
1. Capture traffic baseline: `net_monitor traffic_baseline` on target interface
2. Discover hosts: `net_monitor host_discovery` and compare against known inventory
3. Detect service changes: `net_monitor service_diff` against baseline
4. Monitor DNS: `net_monitor dns_monitor` for exfiltration and tunneling indicators
5. Check for unexpected protocols: `net_monitor protocol_anomaly`

### Key Indicators
- Unknown hosts appearing on network → possible rogue device
- New/removed services → possible compromise or misconfiguration
- Long DNS labels (>40 chars) or deep subdomains (>6 levels) → DNS tunneling
- High-volume DNS to single domain → exfiltration
- Unexpected protocols (ICMP tunnels, non-standard ports) → covert channels

---

## Phase 3: Incident Response

**Goal:** Investigate and contain security incidents.

### Triage Workflow
1. Search logs: `ir_toolkit log_search` for the initial indicator
2. Scan for IOCs: `ir_toolkit ioc_scan` with known bad IPs/domains/hashes
3. Analyze auth logs: `ir_toolkit auth_log_analyze` for brute force / compromise
4. Build timeline: `ir_toolkit timeline_build` across all log sources
5. Get containment plan: `ir_toolkit containment_recommend` based on attack type

### Attack Types (for containment_recommend)
- `brute_force` — credential stuffing, password spraying
- `malware` — malicious code, C2 communication
- `data_exfil` — data theft, unauthorized transfers
- `privilege_escalation` — unauthorized elevation of privileges

### Containment Phases
- **Immediate**: Isolate, preserve evidence, block attacker
- **Short-term**: Patch, harden, deploy detection
- **Long-term**: Architecture improvements, monitoring upgrades

---

## Phase 4: Purple Team Exercises

**Goal:** Correlate red-team attacks with blue-team detections to measure and improve coverage.

### Workflow
1. Execute red-team tests (pentest tools) and record results with MITRE technique IDs
2. Run blue-team detection checks in parallel
3. Generate coverage matrix: `purple_team coverage_matrix` with red/blue results
4. Identify detection gaps: `purple_team detection_gap`
5. Produce exercise report: `purple_team exercise_report`

### Input Format for Red/Blue Results
Red results array: `[{"technique_id":"T1110","technique_name":"Brute Force","success":true}, ...]`
Blue results array: `[{"technique_id":"T1110","detected":true}, ...]`

### Rating Scale
- **≥80% detection rate** → GOOD
- **50-79%** → NEEDS IMPROVEMENT
- **<50%** → CRITICAL — significant gaps

---

## Subagent Delegation

| Task | Delegate To | Tools Available |
|------|-------------|-----------------|
| CIS audits, hardening checks | `defender` | cis_audit, hardening_check, engagement |
| Log analysis, IOC matching, containment | `incident_responder` | ir_toolkit, net_monitor, engagement, security_memory |
| Purple team exercises, coverage analysis | `purple_team` | purple_team, cis_audit, net_monitor, ir_toolkit, engagement, security_memory |

---

## Tool Quick Reference

| Tool | Actions |
|------|---------|
| `cis_audit` | ssh_audit, tls_audit, firewall_audit, patch_check, port_baseline |
| `net_monitor` | traffic_baseline, host_discovery, service_diff, dns_monitor, protocol_anomaly |
| `hardening_check` | ssh_harden, nginx_harden, apache_harden, docker_harden, k8s_harden |
| `ir_toolkit` | log_search, ioc_scan, auth_log_analyze, timeline_build, containment_recommend |
| `purple_team` | coverage_matrix, detection_gap, exercise_report |
| `blackarch` | tshark_capture, bettercap_recon, nmap_scan, shell_exec (allowlisted) |

---

## Live Traffic Capture

**Prerequisite:** The `deck` user must be in the `wireshark` group for tshark/dumpcap access.

### Workflow
1. Capture packets: `blackarch tshark_capture` on `wlan0` with `count=N`
2. Baseline traffic: `net_monitor traffic_baseline` on the same interface
3. Check DNS: `net_monitor dns_monitor` for exfiltration/tunneling
4. Correlate with nmap host inventory from prior scans

### Tips
- On quiet networks, reduce packet count (50–100) to avoid long timeouts
- tshark captures complement nmap scans — nmap finds hosts/services, tshark shows who is actively talking and what protocols are in use
- Use `net_monitor protocol_anomaly` after capture to flag unexpected traffic patterns
- Results auto-ingest to security_memory via KnowledgeIngestMiddleware

---

## Middleware Notes

- **EnforcementMiddleware**: Blue-team tools are NOT pentest-gated — they work without an active engagement. Only red-team tools require engagement/mode/scope checks.
- **KnowledgeIngestMiddleware**: All blue-team tool output is auto-ingested to security_memory. Uses LLM extraction with deterministic parser fallback.
- **Blocked responses**: When enforcement blocks a tool, it returns a `ToolMessage` (not a raw string) to maintain the tool_use/tool_result pairing required by the LLM API.
