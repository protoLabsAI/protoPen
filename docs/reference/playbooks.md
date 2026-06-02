# Playbooks

Playbooks are **declarative tool-chains** — an ordered sequence of tool actions
run by the playbook engine, with no LLM in the loop. They live as YAML in
`playbooks/library/*.yaml` (24 bundled) and are reachable two ways:

- **The agent** — via the `playbook` tool (`playbook(action="list" | "run" | "status", name=…, variables=…)`).
- **The operator** — the **Agents → Playbooks** tab in the [operator console](../guides/operator-console.md): browse the library, fill a recipe's variables, fire it, and watch per-step results.

Both paths share the *same* dispatcher and runner, so a manual run behaves
identically to the agent firing the same playbook.

## Recipe shape

```yaml
name: web_vuln_assessment
description: Nikto + nuclei + targeted web vuln checks against a host.
tags: [vuln, web, assessment]
variables:
  target: ""          # filled at run time; substituted into ${…} params
steps:
  - name: scan_nikto
    tool: web_vuln
    action: nikto_scan
    params: { target: "${target}" }
    on_fail: continue        # stop | continue | skip_remaining
  - name: scan_nuclei
    tool: web_vuln
    action: nuclei_scan
    params: { target: "${target}" }
    condition: scan_nikto.completed   # prior-step / findings.* gating
```

- **Variables** are substituted into string params (`${var}`). The console seeds
  the run form from a recipe's declared defaults.
- **Step references** — `${steps.<name>.output}` feeds a prior step's output into a
  later one.
- **Conditions** — `<step>.completed|failed|skipped`, or `findings.critical|high|…`
  (against the active engagement's findings) gate whether a step runs.

## Mode & the safety gate

Every playbook has a **mode** — `passive`, `active`, or `redteam` — computed
server-side as the **max risk across its steps**. Risk comes from
`config/engagement-config.json` `tool_risk`, which is keyed by **action**
(`cve_nmap` = 2, `wifi_deauth` = 2, `secretsdump` = 3 → clamped to redteam); a
clearly-offensive tag (`redteam`/`exploit`/`post-exploitation`/…) sets a floor.
Across the 24 bundled recipes: ~13 redteam, ~6 active, ~5 passive.

When the **operator** fires a playbook from the console, the same gate the agent
runs under is enforced (`POST /api/playbooks/{name}/run`):

| Playbook mode | Requirement |
|---|---|
| **passive** | Fires freely — *unless* the recipe sets `requires_engagement: true` (see below). |
| **active / redteam** | Needs an **active engagement** whose mode permits it (`risk ≤ mode.value`, same rule as `EngagementManager.is_allowed`) **and** whose **scope covers each step's target**. |

**`requires_engagement` (passive opt-in).** A passive recipe (risk 0) can declare
`requires_engagement: true` to demand an **active engagement + in-scope target**
anyway — without bumping its mode. Used for passive-but-sensitive collection like
**personal OSINT** (profiling a real person), where the tools send nothing to the
target but PII collection should only happen inside an authorized, scoped, logged
engagement. The mode stays `passive`; the engagement (any mode) + scope check still
apply.

A blocked fire returns **HTTP 409** with the reason (no engagement / mode too low
/ target out of scope). Scope is checked with the same `ScopeValidator` the
agent's enforcement middleware uses (`extract_target(action, params)` →
`is_in_scope`), so a redteam recipe can't be run against a host outside the
engagement's declared scope. See [Engagement Modes](./engagement-modes.md).

Every manual fire is recorded in the [audit trail](../guides/operator-console.md)
tagged `source=operator_manual` (`tool=playbook:<name>`).

## A few of the bundled recipes

| Playbook | Mode | Gist |
|---|---|---|
| `external_recon` | passive | OSINT + DNS + perimeter recon on a domain/WAN IP. |
| `personal_osint` | passive¹ | Profile a person from a name/username/email/phone/domain — maigret + holehe + phoneinfoga + theHarvester. ¹`requires_engagement`. |
| `lan_discovery` | redteam | LAN host/service discovery (includes `cve_nmap`). |
| `web_vuln_assessment` | redteam | nikto + nuclei + targeted web checks. |
| `ad_attack` | redteam | AD enumeration → BloodHound → Kerberoast → Certipy. |
| `incident_response` | passive | Blue-team IR / forensics collection. |
| `purple_team_exercise` | redteam | Red + blue with ATT&CK coverage report. |

Run `playbook(action="list")` (agent) or open the Playbooks tab (operator) for the
full library.
