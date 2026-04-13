# Security Research Pivot — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace AI/ML research with security research — CVE tracking, exploit-db monitoring, threat intel, security advisories — and retarget the three research subagents (explorer → threat scanner, analyst → vuln analyst, writer → intel reporter) to keep protoPen current on security issues relevant to its engaged targets.

**Architecture:** The research tools (huggingface, paper_reader, github_trending) get replaced with security-focused equivalents (cve_search, exploit_db, security_feeds). The knowledge store schema pivots from papers/models/digests to advisories/vulnerabilities/threat_intel. Subagents, SOUL.md, guardrails, commands, and docs all update to reflect the security mission.

**Tech Stack:** Python, SQLite + FTS5 + sqlite-vec (hybrid search), LangGraph, existing tool pattern (BaseAction classes)

---

## Milestone 1: Config & Identity (branding + research-config + SOUL.md)

### Task 1: Rename protoResearcher → protoPen globally

**Files:**
- Modify: `server.py` (docstring, model ID, placeholder text, agent card description)
- Modify: `chat_ui.py` (title, branding)
- Modify: `discord_bot.py` (display name)
- Modify: `metrics.py` (metric prefix `protoresearcher_*` → `protopen_*`)
- Modify: `tracing.py` (tags)
- Modify: `audit.py` (docstring)
- Modify: `guardrails.py` (internal API key refs)
- Modify: `static/manifest.json` (name, short_name)
- Modify: `static/sw.js` (cache name)
- Modify: `Dockerfile` (paths)
- Modify: `docker-compose.yml` (container/volume names)
- Modify: `entrypoint.sh` (paths/branding)
- Modify: `config/cliproxy-config.yaml` (token name)
- Modify: `tools/discord_feed.py` (display_name, config path)
- Modify: `tools/rabbit_hole_bridge.py` (source identifiers)
- Modify: `graph/*.py` (docstrings)
- Modify: `knowledge/store.py`, `knowledge/models.py` (docstrings)
- Modify: `lab/runner.py` (docstring)

- [ ] **Step 1: Global find-and-replace `protoResearcher` → `protoPen`**

Run across all `.py`, `.md`, `.json`, `.yaml`, `.yml`, `.sh`, `.js` files. Use case-sensitive replace. Manually review each file to ensure context makes sense (e.g. don't blindly replace in git history comments).

Key replacements:
```
protoResearcher → protoPen
protoresearcher → protopen
protoResearcher -- AI research agent → protoPen -- autonomous pen-testing agent
/opt/protoresearcher/ → /opt/protopen/
protoresearcher-internal → protopen-internal
CACHE_NAME = "protoresearcher-v1" → CACHE_NAME = "protopen-v1"
protoresearcher_llm_calls_total → protopen_llm_calls_total (and all other metrics)
```

- [ ] **Step 2: Update server.py model identity**

In `_openai_models()` (~line 1201):
```python
"id": "protopen",
"owned_by": "protolabs",
```

In the chat UI placeholder (~line 1107):
```python
placeholder="Describe your target scope or ask about recent security intel..."
```

- [ ] **Step 3: Update static/manifest.json**

```json
{
  "name": "protoPen — protoLabs",
  "short_name": "protoPen",
  "description": "Autonomous pen-testing & security research agent",
  ...
}
```

- [ ] **Step 4: Verify no remaining `protoResearcher` references**

```bash
grep -ri "protoresearcher" --include='*.py' --include='*.md' --include='*.json' --include='*.yaml' --include='*.yml' --include='*.js' --include='*.sh' . | grep -v '.git/' | grep -v 'node_modules/' | grep -v '.vitepress/'
```

Expected: 0 results (or only in git-ignored/generated files)

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: rename protoResearcher → protoPen globally"
```

---

### Task 2: Replace research-config.json with security-config.json

**Files:**
- Delete: `config/research-config.json`
- Create: `config/security-config.json`
- Modify: `server.py` (references to research-config.json)
- Modify: `tools/discord_feed.py` (config path)

- [ ] **Step 1: Create `config/security-config.json`**

```json
{
  "instance": {
    "name": "protopen",
    "description": "Steam Deck pen-testing node — security research instance"
  },
  "topics": [
    {
      "name": "cve-critical",
      "description": "Critical and high-severity CVEs from NVD/MITRE",
      "keywords": ["CVE", "critical vulnerability", "RCE", "zero-day", "CVSS 9", "CVSS 10"],
      "priority": 1
    },
    {
      "name": "wireless-security",
      "description": "WiFi, Bluetooth, RF, Sub-GHz, and RFID attack techniques",
      "keywords": ["PMKID", "deauth", "evil twin", "karma attack", "BLE exploit", "replay attack", "Sub-GHz", "RFID clone", "NFC relay"],
      "priority": 1
    },
    {
      "name": "iot-embedded",
      "description": "IoT device vulnerabilities, firmware analysis, embedded security",
      "keywords": ["IoT", "firmware", "JTAG", "UART", "SPI flash", "embedded", "smart home", "router exploit"],
      "priority": 2
    },
    {
      "name": "network-attacks",
      "description": "Network-level attacks, lateral movement, protocol exploits",
      "keywords": ["ARP spoof", "DNS poisoning", "MITM", "lateral movement", "privilege escalation", "SMB", "LLMNR", "NTLM relay"],
      "priority": 2
    },
    {
      "name": "exploit-techniques",
      "description": "New exploit techniques, PoCs, and offensive tool releases",
      "keywords": ["exploit", "PoC", "proof of concept", "buffer overflow", "ROP chain", "shellcode", "metasploit", "cobalt strike"],
      "priority": 2
    },
    {
      "name": "defensive-evasion",
      "description": "EDR bypass, AV evasion, red team tradecraft",
      "keywords": ["EDR bypass", "AV evasion", "AMSI bypass", "obfuscation", "living off the land", "LOLBins", "red team"],
      "priority": 3
    },
    {
      "name": "osint",
      "description": "Open-source intelligence gathering techniques and tools",
      "keywords": ["OSINT", "reconnaissance", "Shodan", "Censys", "subdomain", "credential leak", "data breach", "social engineering"],
      "priority": 3
    },
    {
      "name": "security-tools",
      "description": "New and updated security tools, frameworks, and methodologies",
      "keywords": ["nmap", "burp suite", "nuclei", "ffuf", "hashcat", "john", "impacket", "responder", "bloodhound", "crackmapexec"],
      "priority": 3
    }
  ],
  "feeds": {
    "nvd_scan_interval_hours": 6,
    "exploit_db_scan_interval_hours": 24,
    "github_scan_interval_hours": 24
  },
  "tracked_repos": [
    "projectdiscovery/nuclei",
    "projectdiscovery/httpx",
    "swisskyrepo/PayloadsAllTheThings",
    "carlospolop/PEASS-ng",
    "fortra/impacket",
    "BloodHoundAD/BloodHound",
    "rapid7/metasploit-framework",
    "hashcat/hashcat"
  ],
  "discord": {
    "scan_channels": [],
    "publish_webhook_env": "DISCORD_WEBHOOK_URL"
  },
  "digest": {
    "schedule": "weekly",
    "include_daily_brief": true
  },
  "significance_threshold": "incremental"
}
```

- [ ] **Step 2: Update `server.py` config path references**

Replace all `research-config.json` → `security-config.json` in:
- `_seed_topics()` function
- Any config loading code

- [ ] **Step 3: Update `tools/discord_feed.py` config path**

Replace `/opt/protoresearcher/config/research-config.json` → `/opt/protopen/config/security-config.json`

- [ ] **Step 4: Delete old config**

```bash
rm config/research-config.json
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "config: replace research-config with security-config

Topics: CVE tracking, wireless security, IoT/embedded, network attacks,
exploit techniques, defensive evasion, OSINT, security tools."
```

---

### Task 3: Rewrite SOUL.md for security identity

**Files:**
- Modify: `config/SOUL.md`

- [ ] **Step 1: Rewrite SOUL.md**

Replace all AI/ML research references. The tool inventory "Research Sources" section becomes "Security Intelligence":

```markdown
### Security Intelligence
| Tool | What it does |
|------|-------------|
| cve_search | Query NVD/MITRE CVE database, filter by product/severity/date |
| exploit_db | Search Exploit-DB for PoCs, filter by platform/type |
| security_feeds | Aggregate RSS/Atom from security advisories (vendor, CERT, researcher blogs) |
| browser | Deep-read security advisories, blog posts, PoC writeups |
| github_trending | Track security tool releases and exploit repos |
| discord_feed | Scan security Discord channels for intel |

### Knowledge Management
| Tool | What it does |
|------|-------------|
| security_memory | Store/search advisories, vulnerabilities, threat intel, engagement correlations |
| rabbit_hole_bridge | Ship threat intel to rabbit-hole.io knowledge graph |
```

Replace the 3 research subagents with security equivalents:
```markdown
### Security Research Subagents
| Subagent | Role |
|----------|------|
| threat_scanner | Scans CVE feeds, Exploit-DB, security RSS, GitHub for new threats relevant to engaged systems |
| vuln_analyst | Deep-reads advisories and PoCs, correlates with target intel DB, rates exploitability |
| intel_reporter | Synthesizes threat intel reports, publishes security digests to Discord |
```

Remove all references to: paper_reader, huggingface, research_memory, MoE, quantization, inference, training methods, video generation, multimodal, papers, digests (in the AI research sense).

Keep the pentest identity, hardware toolkit, engagement modes, and all pentest subagents unchanged.

- [ ] **Step 2: Commit**

```bash
git add config/SOUL.md && git commit -m "identity: rewrite SOUL.md for security research mission"
```

---

## Milestone 2: Knowledge Store Schema Pivot

### Task 4: Replace research schema with security schema

**Files:**
- Modify: `knowledge/schema.sql`
- Modify: `knowledge/models.py`
- Modify: `knowledge/store.py`

- [ ] **Step 1: Rewrite `knowledge/schema.sql`**

Replace the research tables (papers, findings, digests, model_releases, sources, topics) with security equivalents:

```sql
-- protoPen security intelligence schema

CREATE TABLE IF NOT EXISTS advisories (
    id              TEXT PRIMARY KEY,          -- CVE-YYYY-NNNNN or vendor advisory ID
    title           TEXT NOT NULL,
    description     TEXT,
    severity        TEXT,                      -- critical, high, medium, low, info
    cvss_score      REAL,
    cvss_vector     TEXT,
    affected_products TEXT DEFAULT '[]',       -- JSON array of CPE strings or product names
    references      TEXT DEFAULT '[]',         -- JSON array of URLs
    exploit_available INTEGER DEFAULT 0,       -- boolean
    patch_available   INTEGER DEFAULT 0,       -- boolean
    source          TEXT,                      -- nvd, exploit-db, vendor, researcher
    source_url      TEXT,
    published_at    TEXT,
    discovered_at   TEXT DEFAULT (datetime('now')),
    notes           TEXT,
    tags            TEXT DEFAULT '[]'          -- JSON array
);

CREATE TABLE IF NOT EXISTS exploits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id     TEXT REFERENCES advisories(id),
    title           TEXT NOT NULL,
    platform        TEXT,                      -- linux, windows, hardware, multi
    exploit_type    TEXT,                      -- remote, local, webapps, dos, shellcode
    source          TEXT,                      -- exploit-db, github, metasploit, custom
    source_url      TEXT,
    code            TEXT,                      -- exploit code or path
    verified        INTEGER DEFAULT 0,
    discovered_at   TEXT DEFAULT (datetime('now')),
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS threat_intel (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    content         TEXT NOT NULL,
    source          TEXT,                      -- feed name, Discord channel, manual
    source_type     TEXT,                      -- rss, discord, github, manual
    topic           TEXT,                      -- matches topics in security-config.json
    intel_type      TEXT,                      -- technique, tool_release, campaign, advisory, ttp
    significance    TEXT DEFAULT 'incremental',-- breakthrough, significant, incremental, noise
    related_advisory_id TEXT REFERENCES advisories(id),
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS topics (
    name            TEXT PRIMARY KEY,
    description     TEXT,
    keywords        TEXT DEFAULT '[]',         -- JSON array
    priority        INTEGER DEFAULT 3,
    active          INTEGER DEFAULT 1,
    created_at      TEXT DEFAULT (datetime('now')),
    last_scanned_at TEXT
);

CREATE TABLE IF NOT EXISTS digests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    title           TEXT,
    content         TEXT,
    digest_type     TEXT DEFAULT 'weekly',     -- weekly, daily_brief, engagement
    topic           TEXT,
    advisories_referenced TEXT DEFAULT '[]',   -- JSON array of advisory IDs
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sources (
    name            TEXT PRIMARY KEY,
    source_type     TEXT,                      -- rss, api, discord, github
    url             TEXT,
    scan_schedule   TEXT,
    last_scanned_at TEXT,
    config          TEXT DEFAULT '{}'          -- JSON
);

-- Full-text search across all security intel
CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
    content,
    source_table,
    source_id,
    tokenize='porter unicode61'
);
```

- [ ] **Step 2: Rewrite `knowledge/models.py`**

Replace research dataclasses with security equivalents:

```python
"""Data models for the protoPen security intelligence store."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Advisory:
    id: str                                    # CVE-YYYY-NNNNN or vendor ID
    title: str
    description: str = ""
    severity: str = ""                         # critical, high, medium, low, info
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    affected_products: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    exploit_available: bool = False
    patch_available: bool = False
    source: str = ""
    source_url: str = ""
    published_at: str = ""
    discovered_at: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class Exploit:
    title: str
    id: Optional[int] = None
    advisory_id: str = ""
    platform: str = ""
    exploit_type: str = ""
    source: str = ""
    source_url: str = ""
    code: str = ""
    verified: bool = False
    discovered_at: str = ""
    notes: str = ""


@dataclass
class ThreatIntel:
    content: str
    id: Optional[int] = None
    source: str = ""
    source_type: str = ""
    topic: str = ""
    intel_type: str = ""                       # technique, tool_release, campaign, advisory, ttp
    significance: str = "incremental"
    related_advisory_id: str = ""
    created_at: str = ""


@dataclass
class Topic:
    name: str
    description: str = ""
    keywords: list[str] = field(default_factory=list)
    priority: int = 3
    active: bool = True
    created_at: str = ""
    last_scanned_at: str = ""


@dataclass
class Digest:
    title: str
    content: str = ""
    id: Optional[int] = None
    digest_type: str = "weekly"
    topic: str = ""
    advisories_referenced: list[str] = field(default_factory=list)
    created_at: str = ""
```

- [ ] **Step 3: Update `knowledge/store.py` methods**

Replace research methods with security equivalents:
- `add_paper()` → `add_advisory()`
- `get_paper()` → `get_advisory()`
- `get_papers()` → `get_advisories()`
- `add_finding()` → `add_threat_intel()`
- `add_digest()` → `add_digest()` (keep, update schema refs)
- `get_digests()` → `get_digests()` (keep)
- `add_model_release()` → `add_exploit()`
- `add_topic()` / `get_topics()` → keep as-is
- Add new: `get_advisories_for_product(product)` — query by affected_products JSON
- Add new: `correlate_with_targets(target_store)` — cross-ref advisories against known hosts/services

Update all SQL table/column references. Update hybrid search to index advisories, exploits, and threat_intel.

- [ ] **Step 4: Commit**

```bash
git add knowledge/ && git commit -m "schema: pivot knowledge store from research to security intel

Tables: advisories, exploits, threat_intel, topics, digests, sources.
Models: Advisory, Exploit, ThreatIntel, Topic, Digest.
Store: add/get/search advisories, exploits, threat intel with hybrid search."
```

---

## Milestone 3: Security Research Tools

### Task 5: Create cve_search tool (replaces huggingface)

**Files:**
- Create: `tools/cve_search.py`
- Delete: `tools/huggingface.py`

- [ ] **Step 1: Create `tools/cve_search.py`**

New tool that queries the NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0) and optionally Exploit-DB. Actions:

```python
"""CVE and vulnerability search tool for protoPen."""
```

Actions:
- `search_cve` — query NVD by keyword, CPE, CVSS severity, date range
- `get_cve` — fetch full details for a specific CVE ID
- `search_by_product` — find CVEs affecting a specific product/version (maps to CPE)
- `recent_critical` — latest critical/high CVEs from last N days

Uses `httpx` for async requests to NVD API. Rate limit: 5 req/30s (no API key) or 50 req/30s (with NVD_API_KEY). Follow existing tool pattern from `tools/portapack.py` (BaseAction subclass with `execute()` method).

- [ ] **Step 2: Delete `tools/huggingface.py`**

```bash
rm tools/huggingface.py
```

- [ ] **Step 3: Commit**

```bash
git add tools/cve_search.py && git rm tools/huggingface.py
git commit -m "feat(tools): add cve_search tool, remove huggingface

Queries NVD API for CVEs by keyword, product, severity, date range.
Replaces HuggingFace model search in the security research pivot."
```

---

### Task 6: Create security_feeds tool (replaces paper_reader)

**Files:**
- Create: `tools/security_feeds.py`
- Delete: `tools/paper_reader.py`

- [ ] **Step 1: Create `tools/security_feeds.py`**

Aggregates security RSS/Atom feeds. Actions:
- `scan_feeds` — fetch and parse configured RSS feeds (CERT advisories, vendor security blogs, researcher feeds)
- `add_feed` — register a new RSS/Atom feed URL
- `list_feeds` — show all configured feeds with last-scan times
- `search_feed_entries` — keyword search across cached entries

Default feeds (configured in security-config.json or hardcoded as fallback):
- US-CERT: https://www.cisa.gov/news.xml
- NVD Recent: https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml  
- Exploit-DB: https://www.exploit-db.com/rss.xml
- The Hacker News: https://feeds.feedburner.com/TheHackersNews
- Krebs on Security: https://krebsonsecurity.com/feed/
- Schneier on Security: https://www.schneier.com/feed/

Uses `feedparser` for RSS/Atom parsing. Stores entries in the `sources` table.

- [ ] **Step 2: Delete `tools/paper_reader.py`**

```bash
rm tools/paper_reader.py
```

- [ ] **Step 3: Commit**

```bash
git add tools/security_feeds.py && git rm tools/paper_reader.py
git commit -m "feat(tools): add security_feeds RSS aggregator, remove paper_reader

Scans CISA, NVD, Exploit-DB, security blogs via RSS/Atom.
Replaces academic paper reader in the security research pivot."
```

---

### Task 7: Retarget github_trending for security repos

**Files:**
- Modify: `tools/github_trending.py`

- [ ] **Step 1: Update default search context**

Change the class description from "Search GitHub for trending and notable AI/ML repositories" to "Search GitHub for trending security tools, exploit PoCs, and offensive/defensive repos."

Update default search terms from ML keywords to security keywords. Update any hardcoded topic filters. Keep the core search/trending functionality — just retarget what it searches for.

- [ ] **Step 2: Commit**

```bash
git add tools/github_trending.py && git commit -m "refactor(tools): retarget github_trending for security repos"
```

---

### Task 8: Replace research_memory with security_memory

**Files:**
- Modify: `tools/research_memory.py` → rename to `tools/security_memory.py`

- [ ] **Step 1: Rename and rewrite**

```bash
mv tools/research_memory.py tools/security_memory.py
```

Update the tool to wrap the new security knowledge store:
- `store_advisory` — save an advisory to the store
- `store_exploit` — save an exploit
- `store_threat_intel` — save threat intelligence
- `search` — hybrid search across all security intel
- `recent` — recent advisories/intel by date
- `correlate` — cross-reference advisory affected_products with target_intel hosts/services
- `stats` — counts by table

- [ ] **Step 2: Commit**

```bash
git add tools/security_memory.py && git rm tools/research_memory.py
git commit -m "feat(tools): rename research_memory → security_memory

Wraps security knowledge store: advisories, exploits, threat intel.
Adds correlate action for cross-ref with target intel DB."
```

---

## Milestone 4: Subagents & Agent Wiring

### Task 9: Replace research subagents with security subagents

**Files:**
- Modify: `graph/subagents/config.py`

- [ ] **Step 1: Replace EXPLORER_CONFIG → THREAT_SCANNER_CONFIG**

```python
THREAT_SCANNER_CONFIG = SubagentConfig(
    name="threat_scanner",
    description="Scans security feeds, CVE databases, Exploit-DB, and GitHub for new threats",
    system_prompt="""You are the threat scanner subagent for protoPen...
    
Scan for new vulnerabilities, exploits, and security tool releases relevant to
the current engagement scope. Prioritize:
1. CVEs affecting products/services found in the target intel database
2. New exploit PoCs for known vulnerabilities in engaged systems
3. Security tool releases relevant to current engagement mode
4. Wireless/RF/IoT threats matching engaged hardware

Workflow:
1. Check security_memory for existing intel on the topic
2. Scan CVE database (cve_search) for recent critical/high CVEs
3. Check security feeds for new advisories
4. Search GitHub for new exploit PoCs and security tools
5. Store all findings via security_memory
6. Cross-correlate with target intel if an engagement is active""",
    tools=["cve_search", "security_feeds", "github_trending", "browser", "security_memory", "rabbit_hole_bridge"],
    max_turns=30,
    disallowed_tools=["task"],
)
```

- [ ] **Step 2: Replace ANALYST_CONFIG → VULN_ANALYST_CONFIG**

```python
VULN_ANALYST_CONFIG = SubagentConfig(
    name="vuln_analyst",
    description="Deep-reads advisories, analyzes exploitability, correlates with target intel",
    system_prompt="""You are the vulnerability analyst subagent for protoPen...

Deep-analyze security advisories and exploits. For each vulnerability:
1. Read the full advisory and any referenced PoC code
2. Assess exploitability against the current target environment
3. Check if affected products match hosts/services in target intel DB
4. Rate severity in context (a critical CVE in an unexposed service is lower priority)
5. Identify attack prerequisites and potential mitigations
6. Store structured analysis via security_memory

Exploitability assessment tiers:
- PROVEN: Working exploit verified against similar target
- LIKELY: PoC exists, conditions match target environment
- POSSIBLE: Vulnerability confirmed, no public exploit yet
- UNLIKELY: Vulnerability exists but mitigating factors present""",
    tools=["cve_search", "security_feeds", "security_memory", "browser", "rabbit_hole_bridge"],
    max_turns=40,
    disallowed_tools=["task"],
)
```

- [ ] **Step 3: Replace WRITER_CONFIG → INTEL_REPORTER_CONFIG**

```python
INTEL_REPORTER_CONFIG = SubagentConfig(
    name="intel_reporter",
    description="Synthesizes threat intel reports and publishes security digests",
    system_prompt="""You are the intelligence reporter subagent for protoPen...

Synthesize security intelligence into actionable reports:
1. Query security_memory for recent advisories, exploits, and threat intel
2. Cross-reference with active engagement findings
3. Organize by severity and relevance to current targets
4. Write structured threat intel digest
5. Publish to Discord via discord_feed webhook

Report structure:
## Critical Alerts (immediate action required)
## New Vulnerabilities (relevant to engaged systems)
## Exploit Activity (new PoCs and tool releases)
## Threat Landscape (broader trends and campaigns)""",
    tools=["security_memory", "discord_feed", "rabbit_hole_bridge"],
    max_turns=20,
    disallowed_tools=["task"],
)
```

- [ ] **Step 4: Update SUBAGENT_REGISTRY**

Replace `explorer`/`analyst`/`writer` entries with `threat_scanner`/`vuln_analyst`/`intel_reporter`.

- [ ] **Step 5: Update REPORTER_CONFIG pentest subagent**

The pentest `reporter` subagent references `research_memory` in its tools — change to `security_memory`.

- [ ] **Step 6: Commit**

```bash
git add graph/subagents/config.py
git commit -m "feat(subagents): replace research subagents with security intel subagents

threat_scanner: CVE feeds, exploit-db, GitHub security tools
vuln_analyst: deep advisory analysis, exploitability assessment
intel_reporter: threat intel digests and Discord publishing"
```

---

### Task 10: Update tool wiring (lg_tools.py, config, prompts)

**Files:**
- Modify: `tools/lg_tools.py`
- Modify: `config/langgraph-config.yaml`
- Modify: `graph/prompts.py`
- Modify: `graph/agent.py`
- Modify: `graph/config.py`

- [ ] **Step 1: Update `tools/lg_tools.py`**

Replace research tool imports:
```python
# Old
from tools.paper_reader import PaperReaderTool
from tools.huggingface import HuggingFaceTool
from tools.research_memory import ResearchMemoryTool

# New
from tools.cve_search import CVESearchTool
from tools.security_feeds import SecurityFeedsTool
from tools.security_memory import SecurityMemoryTool
```

Replace `get_research_tools()` → `get_security_tools()`. Update `get_combined_tools()`. Update `_TOOL_PHASE_MAP` in server.py accordingly.

- [ ] **Step 2: Update `config/langgraph-config.yaml`**

Replace subagent tool lists:
```yaml
subagents:
  threat_scanner: {enabled: true, tools: [cve_search, security_feeds, github_trending, browser, security_memory, rabbit_hole_bridge], max_turns: 30}
  vuln_analyst:   {enabled: true, tools: [cve_search, security_feeds, security_memory, browser, rabbit_hole_bridge], max_turns: 40}
  intel_reporter: {enabled: true, tools: [security_memory, discord_feed, rabbit_hole_bridge], max_turns: 20}
  recon:          {enabled: true, tools: [device_manager, portapack, flipper, marauder, blackarch, engagement, target_intel], max_turns: 30}
  exploit:        {enabled: true, tools: [device_manager, portapack, flipper, marauder, blackarch, engagement, target_intel], max_turns: 25}
  reporter:       {enabled: true, tools: [engagement, security_memory, discord_feed, target_intel], max_turns: 20}
```

Rename `knowledge.db_path` from `research.db` to `security.db`.

- [ ] **Step 3: Update `graph/prompts.py`**

Replace research delegation rules with security delegation rules. The subagent delegation section auto-generates from SUBAGENT_REGISTRY, so mostly this involves updating any hardcoded guidelines text.

- [ ] **Step 4: Update `graph/agent.py` task tool docstring**

Update `_build_task_tool()` to reference security subagents instead of research ones.

- [ ] **Step 5: Update `graph/config.py` defaults**

Replace explorer/analyst/writer default tool configs with threat_scanner/vuln_analyst/intel_reporter.

- [ ] **Step 6: Commit**

```bash
git add tools/lg_tools.py config/langgraph-config.yaml graph/
git commit -m "wiring: connect security tools and subagents to agent graph"
```

---

## Milestone 5: Server Commands & Guardrails

### Task 11: Replace research slash commands

**Files:**
- Modify: `server.py`

- [ ] **Step 1: Replace command handlers**

- `/topics` → show security topics from security-config.json (keep, update content)
- `/agenda` → show security intel stats: advisories, exploits, threat_intel counts + topics by priority
- `/papers` → replace with `/cves [query]` — search advisories by keyword or CVE ID
- `/recent` → show recent advisories with severity and date
- `/publish` → generate security digest instead of research digest

Update the help text, command dispatch, and all handler functions.

- [ ] **Step 2: Update `_TOOL_PHASE_MAP`**

```python
_TOOL_PHASE_MAP = {
    "cve_search": "threat_scanner",
    "security_feeds": "threat_scanner",
    "github_trending": "threat_scanner",
    "web_search": "threat_scanner",
    "web_fetch": "threat_scanner",
    "browser": "threat_scanner",
    "security_memory": "vuln_analyst",
    "message": "intel_reporter",
}
```

- [ ] **Step 3: Update `_seed_topics()`**

Read from `security-config.json` instead of `research-config.json`.

- [ ] **Step 4: Update tool registration (nanobot backend)**

Replace PaperReaderTool/HuggingFaceTool/ResearchMemoryTool with CVESearchTool/SecurityFeedsTool/SecurityMemoryTool.

- [ ] **Step 5: Commit**

```bash
git add server.py && git commit -m "commands: replace research commands with security intel commands

/cves replaces /papers. /agenda shows security stats.
/publish generates security digest. /recent shows advisories."
```

---

### Task 12: Update guardrails for security scope

**Files:**
- Modify: `guardrails.py`

- [ ] **Step 1: Update `_GUARDRAIL_PROMPT`**

Replace AI/ML scope scoring with security scope:
```python
_GUARDRAIL_PROMPT = """Score this query's relevance to cybersecurity, pen testing, and security research on a scale of 0-100.

High relevance (70-100): vulnerability analysis, CVE lookup, exploit techniques, network security, wireless attacks, RFID/NFC security, IoT hacking, red team tradecraft, OSINT, security tools, threat intelligence, system hardening, incident response, forensics, malware analysis.

Medium relevance (30-70): general IT/networking, system administration, DevOps security, programming (when security-related), hardware hacking, radio frequency topics.

Low relevance (0-30): unrelated general knowledge, entertainment, cooking, sports, pure academic research unrelated to security.

Return ONLY the integer score."""
```

- [ ] **Step 2: Update keyword bypass list**

Replace ML keywords (moe, rag, rlhf, dpo, lora) with security keywords (cve, exploit, vulnerability, pentest, nmap, recon, deauth, mitm, payload, shellcode, hash, crack, bypass, evasion, lateral, pivot, exfiltrate).

- [ ] **Step 3: Update query rewriting keywords**

Replace ML keyword expansion with security keyword expansion.

- [ ] **Step 4: Commit**

```bash
git add guardrails.py && git commit -m "guardrails: retarget scope validation for security research"
```

---

### Task 13: Update A2A agent card skills

**Files:**
- Modify: `server.py` (AGENT_CARD)

- [ ] **Step 1: Replace `deep_research` and `summarize` skills**

```python
{
    "id": "threat_intel",
    "name": "Threat Intelligence",
    "description": (
        "Research security threats relevant to a target scope. Scans CVE databases, "
        "Exploit-DB, security feeds, and GitHub for vulnerabilities, exploits, and "
        "attack techniques. Correlates findings with target intel database."
    ),
    "inputModes": ["text/plain"],
    "outputModes": ["text/markdown"],
},
{
    "id": "security_digest",
    "name": "Security Digest",
    "description": (
        "Generate a threat intelligence digest — recent CVEs, exploit activity, and "
        "security tool releases relevant to engaged systems. Optionally scoped to a "
        "topic or product."
    ),
    "inputModes": ["text/plain"],
    "outputModes": ["text/markdown"],
},
```

- [ ] **Step 2: Update agent card description**

Remove "AI/ML research capabilities" from the description. Replace with "security intelligence — CVE tracking, exploit monitoring, threat analysis."

- [ ] **Step 3: Commit**

```bash
git add server.py && git commit -m "a2a: replace research skills with threat_intel and security_digest"
```

---

## Milestone 6: Skills & Docs

### Task 14: Replace research skill with security research skill

**Files:**
- Delete: `skills/research/SKILL.md`
- Create: `skills/security-research/SKILL.md`

- [ ] **Step 1: Create `skills/security-research/SKILL.md`**

Security research workflows:
- **Threat Scan**: CVE search → security feeds → GitHub → correlate with targets → store
- **Advisory Deep Dive**: fetch advisory → read PoC → assess exploitability → correlate → store
- **Engagement Intel**: pull recent advisories for engaged product/services → triage → report
- **Security Digest**: query security_memory → organize by severity → write → publish

Exploitability assessment guide: PROVEN / LIKELY / POSSIBLE / UNLIKELY.
Severity context guide: how to rate a CVE relative to the current engagement scope.

- [ ] **Step 2: Delete old skill**

```bash
rm -rf skills/research/
```

- [ ] **Step 3: Update `graph/prompts.py` skill loading path**

Replace `skills/research/SKILL.md` → `skills/security-research/SKILL.md`.

- [ ] **Step 4: Commit**

```bash
git add skills/ graph/prompts.py && git commit -m "skill: replace research skill with security-research skill

Workflows: threat scan, advisory deep dive, engagement intel, digest."
```

---

### Task 15: Update all docs for security pivot

**Files:**
- Modify: `docs/index.md`
- Modify: `docs/tutorials/index.md`
- Modify: `docs/guides/a2a-integration.md`
- Modify: `docs/guides/rabbit-hole-mcp.md`
- Modify: `docs/reference/api-endpoints.md`
- Modify: `docs/reference/chat-commands.md`
- Modify: `docs/reference/tools.md`
- Modify: `docs/reference/environment-variables.md`
- Modify: `docs/reference/configuration.md`
- Modify: `docs/explanation/architecture.md`
- Modify: `docs/explanation/knowledge-search.md`
- Modify: `docs/explanation/security-model.md`

- [ ] **Step 1: Update landing page `docs/index.md`**

Replace "AI Research" feature card with "Security Intelligence" — CVE tracking, exploit monitoring, threat feeds, correlation with target intel.

- [ ] **Step 2: Update all docs referencing research tools/subagents/commands**

Systematic replacements across all docs:
- `deep_research` → `threat_intel`
- `summarize` → `security_digest`
- `explorer/analyst/writer` → `threat_scanner/vuln_analyst/intel_reporter`
- `paper_reader/huggingface/research_memory` → `cve_search/security_feeds/security_memory`
- `/papers` → `/cves`
- Research examples → security examples
- AI/ML references → security references

- [ ] **Step 3: Update reference/tools.md**

Add cve_search, security_feeds, security_memory tool tables. Remove huggingface, paper_reader, research_memory.

- [ ] **Step 4: Update explanation/architecture.md**

Replace "Research Domain" subagent table with "Security Intelligence Domain". Update ASCII diagram.

- [ ] **Step 5: Update explanation/knowledge-search.md**

Reframe from papers/digests to advisories/exploits/threat_intel.

- [ ] **Step 6: Commit**

```bash
git add docs/ && git commit -m "docs: update all pages for security research pivot"
```

---

### Task 16: Rewrite README.md

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Rewrite README**

Complete rewrite as protoPen (not protoResearcher). Structure:
1. Title + tagline (autonomous pen-testing + security research agent)
2. What it does (hardware-in-the-loop pentesting + security intel)
3. Architecture diagram (updated for security tools)
4. Quick Start (Steam Deck native + Docker)
5. A2A Protocol (with security skill examples)
6. Security Intelligence (CVE tracking, feeds, correlation)
7. Chat Commands (updated table)
8. Engagement Modes (PASSIVE/ACTIVE/REDTEAM)
9. Hardware (PortaPack, Flipper, Marauder)
10. Environment Variables
11. Stack
12. Part of protoLabs table (update role description)

- [ ] **Step 2: Commit**

```bash
git add README.md && git commit -m "docs: rewrite README for protoPen security mission"
```

---

## Milestone 7: Verify & Deploy

### Task 17: Build and smoke test

- [ ] **Step 1: Run linter/type check**

```bash
cd /Users/kj/dev/protoPen
python -m py_compile server.py
python -m py_compile tools/cve_search.py
python -m py_compile tools/security_feeds.py
python -m py_compile tools/security_memory.py
python -m py_compile knowledge/store.py
python -m py_compile graph/subagents/config.py
```

- [ ] **Step 2: Build docs**

```bash
npm run docs:build
```

- [ ] **Step 3: Verify no remaining research references**

```bash
grep -ri "protoresearcher\|huggingface\|paper_reader\|research_memory\|moe.scaling\|quantization.*model\|inference.optim" \
  --include='*.py' --include='*.md' --include='*.json' --include='*.yaml' . \
  | grep -v '.git/' | grep -v 'node_modules/' | grep -v '.vitepress/' | grep -v '.plans/'
```

- [ ] **Step 4: Deploy to Steam Deck and verify A2A**

```bash
git push
ssh deck@steamdeck "cd ~/protoPen && git pull && pip install feedparser httpx && systemctl --user restart protopen"
sleep 5
# Test security A2A query
ssh deck@steamdeck "curl -s -X POST http://localhost:7870/a2a \
  -H 'Content-Type: application/json' \
  -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"message/send\",\"params\":{\"message\":{\"role\":\"user\",\"parts\":[{\"kind\":\"text\",\"text\":\"Search for recent critical CVEs related to OpenSSH\"}]}}}' | python3 -m json.tool | head -30"
```

- [ ] **Step 5: Final commit if any fixes needed**

```bash
git add -A && git commit -m "fix: address issues found during smoke test" && git push
```
