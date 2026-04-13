# Configuration Files

protoPen uses several configuration files located in the `config/` directory. This directory is bind-mounted into the container at `/opt/protoresearcher/config/`, so changes on the host take effect after a container restart.

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
  explorer:
    enabled: true
    tools: [discord_feed, huggingface, github_trending, browser, rabbit_hole_bridge]
    max_turns: 30
  analyst:
    enabled: true
    tools: [paper_reader, research_memory, browser, rabbit_hole_bridge]
    max_turns: 40
  # ... (writer, recon, exploit, reporter)

middleware:
  knowledge: true
  audit: true
  memory: true

knowledge:
  db_path: /sandbox/knowledge/research.db
  embed_model: qwen3-embedding:0.6b
  top_k: 10
  search_mode: hybrid
  enrich_chunks: true
```

### Key Sections

| Section | Description |
|---|---|
| `model` | LLM provider, model name, API base, generation parameters |
| `subagents` | Per-subagent tool allowlists, enable/disable, max turns |
| `middleware` | Toggle knowledge injection, audit logging, memory consolidation |
| `knowledge` | Embedding model, vector search config, contextual enrichment setting |

---

## nanobot-config.json

Configuration for the nanobot (legacy) agent backend.

**Path:** `config/nanobot-config.json`

This follows the standard nanobot configuration format. Refer to the nanobot documentation for the full schema. Key settings include model selection, provider configuration, tool restrictions, and workspace paths.

---

## research-config.json

Default research topics seeded on startup.

**Path:** `config/research-config.json`

Contains a `topics` array, each with `name`, `keywords`, and `priority`. Topics are seeded into the knowledge store on first launch.

---

## SOUL.md

The agent's identity and personality prompt.

**Path:** `config/SOUL.md`

This file defines who protoPen is, its values, and behavioral guidelines. It is injected as the first section of the system prompt. Edit this file to customize the agent's personality.
