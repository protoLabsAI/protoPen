# Configuration Files

protoPen uses several configuration files located in the `config/` directory. This directory is bind-mounted into the container at `/opt/protopen/config/`, so changes on the host take effect after a container restart.

## engagement-config.json

Primary configuration for pen testing operations: hardware devices, engagement defaults, and tool risk levels.

**Path:** `config/engagement-config.json`

### Structure

```json
{
  "instance": {
    "name": "protoPen",
    "description": "Mobile pen testing agent — Steam Deck + peripherals"
  },
  "devices": {
    "portapack": {
      "type": "serial",
      "serial_number": "",
      "fallback_port": "/dev/ttyACM0",
      "prompt": "ch>",
      "timeout": 3
    },
    "flipper": {
      "type": "serial",
      "serial_number": "",
      "fallback_port": "/dev/ttyACM1",
      "prompt": ">: ",
      "timeout": 3
    },
    "marauder": {
      "type": "serial",
      "serial_number": "",
      "fallback_port": "/dev/ttyUSB0",
      "baud_rate": 115200,
      "timeout": 3
    },
    "wifi_adapter": {
      "type": "network",
      "interface": "wlan1",
      "monitor_interface": "wlan1mon"
    }
  },
  "engagement": {
    "default_mode": "passive",
    "workspace_dir": "/home/deck/engagements",
    "alert_webhook": "",
    "alert_channel_id": ""
  },
  "tool_risk": {
    "rf_scan": 0,
    "wifi_deauth": 2,
    "...": "..."
  }
}
```

### Key Sections

| Section | Description |
|---|---|
| `instance` | Identity metadata for this protoPen node |
| `devices` | Serial connection settings for each hardware device |
| `engagement` | Default engagement mode, workspace directory, Discord alert webhook |
| `risk_levels` | Maps mode names to integer levels (passive=0, active=1, redteam=2) |
| `tool_risk` | Maps individual tool actions to their required risk level |

---

## langgraph-config.yaml

Configuration for the LangGraph agent backend (used when `AGENT_BACKEND=langgraph`).

**Path:** `config/langgraph-config.yaml`

### Structure

```yaml
model:
  provider: gateway
  name: claude-sonnet-4-6
  api_base: http://ava:4000/v1
  api_key: ""
  temperature: 0.3
  max_tokens: 4096
  max_iterations: 75

subagents:
  threat_scanner:
    enabled: true
    tools: [cve_search, security_feeds, github_trending, browser, security_memory]
    max_turns: 30
  vuln_analyst:
    enabled: true
    tools: [cve_search, security_feeds, security_memory, browser, target_intel]
    max_turns: 40
  # ... (intel_reporter, recon, exploit, reporter)

middleware:
  knowledge: true
  audit: true
  memory: true

knowledge:
  db_path: /sandbox/knowledge/security.db
  embed_model: qwen3-embedding
  top_k: 10
  search_mode: hybrid
  enrich_chunks: true

# Skills (SKILL.md methodology). Progressive disclosure (default on): a lightweight
# <available_skills> catalog (name + description) is injected each turn and the
# agent pulls a full body on demand via the load_skill tool — instead of injecting
# matched skill bodies. user_only skills are catalog-hidden, reachable only via
# /skill. Set progressive_disclosure: false for the legacy top-k full-body inject.
skills:
  enabled: true
  dir: /sandbox/skills
  db_path: /sandbox/skills.db
  top_k: 5
  progressive_disclosure: true

# Progressive tool disclosure (ADR 0005). OFF by default. protoPen binds ~80
# tools; with deferral on, most tool schemas are withheld from the model each
# turn (every tool stays callable) and the agent loads them on demand via the
# `search_tools` meta-tool. `keep` overrides the always-exposed base set
# (orchestration + task/schedule management + search_tools).
tools:
  deferred:
    enabled: false
    keep: []          # e.g. [task, run_workflow, create_task, search_tools]

# Goal mode (autonomy) — re-invoke the agent toward a verifier-backed condition
# (set with /goal in chat, or by the agent via the set_goal tool). Verifiers are
# read-only, no shell: findings / targets / task / llm. See explanation/autonomy.
goals:
  enabled: true
  max_iterations: 10
  no_progress_limit: 4
  monitor_interval_s: 60      # out-of-band cadence for monitor goals (<=0 disables)
  dream_cadence_cron: ""      # 5-field cron to seed a recurring /dream pass (blank = off)
```

### Key Sections

| Section | Description |
|---|---|
| `model` | LLM provider, model name, API base, generation parameters |
| `subagents` | Per-subagent tool allowlists, enable/disable, max turns |
| `middleware` | Toggle knowledge injection, audit logging, memory consolidation |
| `knowledge` | Embedding model, vector search config, contextual enrichment setting |
| `skills` | SKILL.md retrieval — enable, dir, db path, top-k, `progressive_disclosure` (catalog + load_skill) |
| `workflows` | Declarative subagent recipes — enable, writable dir |
| `tools.deferred` | Progressive tool disclosure (ADR 0005) — `enabled`, `keep` |
| `goals` | Goal mode (autonomy) — `enabled`, `max_iterations`, `no_progress_limit`, `monitor_interval_s` (monitor-goal cadence), `dream_cadence_cron` (scheduled memory hygiene) |

---

## security-config.json

Default security topics and feed configuration seeded on startup.

**Path:** `config/security-config.json`

Contains a `topics` array (CVE tracking, wireless security, exploit techniques, etc.), each with `name`, `keywords`, and `priority`. Also includes `feeds` configuration for scan intervals and `tracked_repos` for security tool monitoring. Topics are seeded into the knowledge store on first launch.

---

## SOUL.md

The agent's identity and personality prompt.

**Path:** `config/SOUL.md`

This file defines who protoPen is, its values, and behavioral guidelines. It is injected as the first section of the system prompt. Edit this file to customize the agent's personality.
