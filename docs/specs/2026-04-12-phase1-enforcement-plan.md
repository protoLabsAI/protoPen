# Phase 1: Enforcement & Safety Foundation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add hard middleware enforcement of engagement mode, scope, kill chain phase, and rate limits to the protoPen agent graph. Upgrade audit trail to SQLite. Lock down shell_exec.

**Architecture:** New `enforcement/` package with ScopeValidator, KillChainPhase, and RateLimiter. New EnforcementMiddleware in `graph/middleware/` wired first in the chain. New EngagementStore for SQLite audit trail. All enforce at the tool execution layer, not via prompt instructions.

**Tech Stack:** Python 3.9, LangChain AgentMiddleware protocol, SQLite, ipaddress stdlib, pytest

**Baseline:** 244 passing tests. Run `python3 -m pytest tests/ --tb=short` to confirm green before and after every task.

**Repo root:** `/Users/kj/dev/protoPen`

---

## Codebase Map (read these first)

| File | What it does | Why it matters |
|------|-------------|----------------|
| `graph/agent.py` | Builds the LangGraph agent. `_build_middleware()` (line 21) returns an ordered list of `AgentMiddleware` instances. `create_researcher_graph()` (line 101) takes `config`, `knowledge_store`, `include_subagents`, `sitrep`. | You will add `EnforcementMiddleware` first in the middleware chain and pass `engagement_manager` through. |
| `graph/middleware/audit.py` | `AuditMiddleware(AgentMiddleware)` — the canonical middleware pattern. `wrap_tool_call(request, handler)` / `awrap_tool_call(request, handler)`. Reads `request.tool_call["name"]` and `request.tool_call["args"]`. Calls `handler(request)` to proceed, or raises to abort. Returns the `ToolMessage` result. | Copy this pattern exactly for `EnforcementMiddleware`. |
| `graph/middleware/__init__.py` | Empty file. | The middleware package already exists — just add new files. |
| `guardrails.py` (line 194-228) | `_PENTEST_TOOL_PREFIXES` set: `{"portapack", "flipper", "marauder", "blackarch", "engagement", "device_manager"}`. `check_engagement_mode(tool_name, engagement_manager)` returns `{"pass": bool, "mode": str, "reason": str}`. Currently NOT wired as middleware — only used for informational checks. | Reuse `_PENTEST_TOOL_PREFIXES` in `EnforcementMiddleware`. Import it: `from guardrails import _PENTEST_TOOL_PREFIXES`. |
| `tools/engagement.py` | `EngagementMode(IntEnum)` PASSIVE=0, ACTIVE=1, REDTEAM=2. `EngagementManager(Tool)` with `is_allowed(tool_name) -> bool`, `mode` property, `_tool_risk` dict, `start()`, `end()`, `log_finding()`. `start()` takes `name`, `scope`, `mode` params. The manager's `active_engagement` dict has `name`, `scope`, `mode`, `started_at`, `workspace` keys. `findings` is a list of dicts. | You will add `max_phase` and `scope_config` attrs to the manager instance. You will modify `start()` to accept and store `max_phase` and `scope` config. |
| `tools/blackarch.py` | `BlackArchTool(Tool)` with `shell_exec()` at line 174. `_BLOCKED_COMMANDS` (line 24) — hard deny. `_SAFE_COMMANDS` (line 32) — known-good. Current logic: if command in `_BLOCKED_COMMANDS` → block; if not in `_SAFE_COMMANDS` → warn but ALLOW. This is the gap — unknown commands slip through. | You will flip shell_exec to deny-by-default: block if not in `_SAFE_COMMANDS`, unless `force=True` AND mode is REDTEAM. |
| `tools/lg_tools.py` | LangChain `@tool` adapters. `_init_pentest_singletons()` (line 355) lazy-inits `_engagement`, `_blackarch`, etc. from `config/engagement-config.json`. `_engagement` is the module-level singleton. `get_combined_tools()` returns all tool functions. | You need to expose `_engagement` so `graph/agent.py` can pass it to middleware. Add a `get_engagement_manager()` accessor. |
| `config/engagement-config.json` | Has `tool_risk` (38 actions mapped to 0/1/2), `engagement.default_mode`, `risk_levels`, device configs. No `scope`, `max_phase`, or `rate_limits` keys yet. | You will add `scope`, `max_phase`, and `rate_limits` sections. |
| `knowledge/target_store.py` | `TargetStore` — the established SQLite pattern. Uses `_get_db()` lazy init, `PRAGMA journal_mode=WAL`, `PRAGMA foreign_keys=ON`, `Path.parent.mkdir(parents=True)`, `row_factory = sqlite3.Row`, loads schema from `.sql` file. | Follow this pattern exactly for `EngagementStore`. |
| `knowledge/target_schema.sql` | The SQL schema pattern — `CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`, `AUTOINCREMENT` PKs, `TEXT` timestamps, FK references. | Follow this pattern for `engagement_schema.sql`. |
| `server.py` | `_init_langgraph_agent()` (line ~105) calls `create_researcher_graph()`. This is where the graph is built. Does NOT currently pass engagement_manager. | You will modify this to pass engagement_manager to the graph builder. |
| `tests/test_engagement.py` | Test pattern: `@pytest.fixture` for config (loads real `config/engagement-config.json`), `tmp_path` for workspace, tests are sync/async methods in classes. | Follow this test pattern. |
| `tests/test_blackarch.py` | Test pattern: `@patch("tools.blackarch.asyncio.create_subprocess_exec")`, `AsyncMock()` for process, `@pytest.mark.asyncio` on async tests. | Follow this pattern for new blackarch tests. |

---

## Task 1: ScopeValidator Class

**Create:** `enforcement/__init__.py`, `enforcement/scope.py`
**Test:** `tests/test_scope_validator.py`

### Step 1.1 — Create the enforcement package

- [ ] Create `enforcement/__init__.py`:

```python
"""Enforcement & safety layer for protoPen.

Hard enforcement of engagement scope, kill chain phases, and rate limits
at the middleware layer. All checks happen before tool execution — not via
prompt instructions.
"""
```

**File:** `enforcement/__init__.py`

### Step 1.2 — Write tests first

- [ ] Create `tests/test_scope_validator.py`:

```python
"""Tests for ScopeValidator — engagement scope enforcement."""
import pytest

from enforcement.scope import ScopeValidator


class TestCIDRScope:
    def test_ip_in_cidr(self):
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        assert sv.is_in_scope("192.168.4.1") is True

    def test_ip_outside_cidr(self):
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        assert sv.is_in_scope("10.0.0.1") is False

    def test_ip_in_multi_cidr(self):
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24", "10.0.0.0/8"]})
        assert sv.is_in_scope("10.1.2.3") is True

    def test_single_host_cidr(self):
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.100/32"]})
        assert sv.is_in_scope("192.168.4.100") is True
        assert sv.is_in_scope("192.168.4.101") is False

    def test_url_extracts_ip(self):
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        assert sv.is_in_scope("http://192.168.4.50:8080/admin") is True

    def test_invalid_ip_returns_false(self):
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        assert sv.is_in_scope("not-an-ip") is False

    def test_empty_target_returns_false(self):
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        assert sv.is_in_scope("") is False


class TestDomainScope:
    def test_exact_domain(self):
        sv = ScopeValidator({"type": "domain", "targets": ["example.com"]})
        assert sv.is_in_scope("example.com") is True

    def test_wildcard_domain(self):
        sv = ScopeValidator({"type": "domain", "targets": ["*.example.com"]})
        assert sv.is_in_scope("sub.example.com") is True

    def test_wildcard_rejects_other_domain(self):
        sv = ScopeValidator({"type": "domain", "targets": ["*.example.com"]})
        assert sv.is_in_scope("evil.com") is False

    def test_url_extracts_domain(self):
        sv = ScopeValidator({"type": "domain", "targets": ["*.example.com"]})
        assert sv.is_in_scope("https://api.example.com/v1/users") is True

    def test_domain_case_insensitive(self):
        sv = ScopeValidator({"type": "domain", "targets": ["*.Example.COM"]})
        assert sv.is_in_scope("sub.example.com") is True

    def test_multi_domain(self):
        sv = ScopeValidator({"type": "domain", "targets": ["*.example.com", "*.test.org"]})
        assert sv.is_in_scope("api.test.org") is True
        assert sv.is_in_scope("evil.net") is False


class TestAnyScope:
    def test_any_allows_everything(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.is_in_scope("1.2.3.4") is True
        assert sv.is_in_scope("evil.com") is True
        assert sv.is_in_scope("") is True


class TestExtractTarget:
    def test_nmap_scan_extracts_target(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("nmap_scan", {"target": "192.168.1.1"}) == "192.168.1.1"

    def test_nmap_vuln_scan_extracts_target(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("nmap_vuln_scan", {"target": "10.0.0.1"}) == "10.0.0.1"

    def test_gobuster_extracts_url(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("gobuster_scan", {"url": "http://example.com"}) == "http://example.com"

    def test_nikto_extracts_url(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("nikto_scan", {"url": "https://10.0.0.1"}) == "https://10.0.0.1"

    def test_shell_exec_extracts_from_command(self):
        sv = ScopeValidator({"type": "any"})
        # shell_exec has no structured target — returns None
        assert sv.extract_target("shell_exec", {"command": "nmap 1.2.3.4"}) is None

    def test_unknown_tool_returns_none(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("unknown_tool", {"foo": "bar"}) is None

    def test_missing_arg_returns_none(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("nmap_scan", {}) is None

    def test_bettercap_recon_extracts_interface_not_target(self):
        sv = ScopeValidator({"type": "any"})
        # bettercap_recon targets a local interface, not a remote target
        assert sv.extract_target("bettercap_recon", {"interface": "eth0"}) is None

    def test_wifi_deauth_extracts_target(self):
        sv = ScopeValidator({"type": "any"})
        # Marauder deauth doesn't have a target arg in the current schema
        assert sv.extract_target("wifi_deauth", {"indices": "0,1"}) is None

    def test_hashcat_has_no_remote_target(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("hashcat_crack", {"hash_file": "/tmp/hashes"}) is None


class TestEmptyAndMalformedConfig:
    def test_empty_targets_cidr(self):
        sv = ScopeValidator({"type": "cidr", "targets": []})
        assert sv.is_in_scope("1.2.3.4") is False

    def test_missing_targets_key(self):
        sv = ScopeValidator({"type": "cidr"})
        assert sv.is_in_scope("1.2.3.4") is False

    def test_unknown_type_defaults_to_deny(self):
        sv = ScopeValidator({"type": "bogus", "targets": ["*"]})
        assert sv.is_in_scope("1.2.3.4") is False
```

- [ ] Run tests — confirm they fail (module does not exist yet):

```bash
python3 -m pytest tests/test_scope_validator.py --tb=short 2>&1 | tail -5
# Expected: ERROR — ModuleNotFoundError: No module named 'enforcement'
```

### Step 1.3 — Implement ScopeValidator

- [ ] Create `enforcement/scope.py`:

```python
"""Scope validation for engagement target enforcement.

Validates that tool targets (IPs, hostnames, URLs) are within the defined
engagement scope before allowing execution.
"""
from __future__ import annotations

import ipaddress
import fnmatch
from typing import Optional
from urllib.parse import urlparse


# Maps tool action names to the argument key that contains the target.
# Tools not listed here have no extractable remote target.
_TOOL_TARGET_ARG: dict[str, str] = {
    # BlackArch tools
    "nmap_scan": "target",
    "nmap_vuln_scan": "target",
    "nikto_scan": "url",
    "gobuster_scan": "url",
    # Engagement-level — not a remote target
    # RF/WiFi/BLE tools typically target local interfaces or broadcast, not remote hosts
}


class ScopeValidator:
    """Validates that targets fall within the engagement scope.

    Scope config format:
        {"type": "cidr",   "targets": ["192.168.4.0/24", "10.0.0.0/8"]}
        {"type": "domain", "targets": ["*.example.com"]}
        {"type": "any"}                                   # allow everything

    Args:
        scope_config: Dict with "type" and optional "targets" keys.
    """

    def __init__(self, scope_config: dict):
        self._type = scope_config.get("type", "any")
        self._targets = scope_config.get("targets", [])
        # Pre-parse CIDR networks for fast lookup
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        if self._type == "cidr":
            for t in self._targets:
                try:
                    self._networks.append(ipaddress.ip_network(t, strict=False))
                except ValueError:
                    pass  # skip malformed CIDR entries

    def is_in_scope(self, target: str) -> bool:
        """Check if a target string (IP, hostname, or URL) is within scope.

        Returns True if in scope, False otherwise. Empty targets return False
        unless scope type is "any".
        """
        if self._type == "any":
            return True

        if not target:
            return False

        if self._type == "cidr":
            return self._check_cidr(target)
        elif self._type == "domain":
            return self._check_domain(target)

        # Unknown scope type — deny by default
        return False

    def extract_target(self, tool_name: str, args: dict) -> Optional[str]:
        """Extract the remote target from a tool call's arguments.

        Returns the target string if the tool has a known target argument,
        or None if the tool doesn't target a remote host (e.g. local-only
        operations like hashcat, airmon, bettercap_recon).
        """
        arg_key = _TOOL_TARGET_ARG.get(tool_name)
        if arg_key is None:
            return None
        value = args.get(arg_key)
        if not value:
            return None
        return str(value)

    def _check_cidr(self, target: str) -> bool:
        """Check if target IP is within any configured CIDR range."""
        ip = self._extract_ip(target)
        if ip is None:
            return False
        return any(ip in net for net in self._networks)

    def _check_domain(self, target: str) -> bool:
        """Check if target hostname matches any configured domain pattern."""
        hostname = self._extract_hostname(target)
        if not hostname:
            return False
        hostname_lower = hostname.lower()
        return any(
            fnmatch.fnmatch(hostname_lower, pattern.lower())
            for pattern in self._targets
        )

    @staticmethod
    def _extract_ip(target: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """Try to extract an IP address from a target string (plain IP or URL)."""
        # Try direct parse first
        try:
            return ipaddress.ip_address(target)
        except ValueError:
            pass

        # Try extracting from URL
        try:
            parsed = urlparse(target)
            host = parsed.hostname
            if host:
                return ipaddress.ip_address(host)
        except (ValueError, TypeError):
            pass

        return None

    @staticmethod
    def _extract_hostname(target: str) -> Optional[str]:
        """Extract hostname from a target string (plain hostname or URL)."""
        # Try URL parse first
        try:
            parsed = urlparse(target)
            if parsed.hostname:
                return parsed.hostname
        except (ValueError, TypeError):
            pass

        # If no scheme, treat the whole string as a hostname
        # (filter out things that look like IPs)
        try:
            ipaddress.ip_address(target)
            return None  # It's an IP, not a hostname
        except ValueError:
            pass

        # Return as hostname if it looks like one (contains a dot or is plain text)
        if target and not target.startswith("/"):
            return target

        return None
```

- [ ] Run tests — confirm all pass:

```bash
python3 -m pytest tests/test_scope_validator.py --tb=short -q
# Expected: ~27 passed
```

- [ ] Run full suite to verify no regressions:

```bash
python3 -m pytest tests/ --tb=short -q
# Expected: 244 passed (original) + new tests = ~271 passed
```

- [ ] Commit:

```bash
git add enforcement/ tests/test_scope_validator.py
git commit -m "feat: ScopeValidator for engagement target enforcement"
```

---

## Task 2: KillChainPhase Enum and Phase Tagging

**Create:** `enforcement/phases.py`
**Test:** `tests/test_kill_chain.py`

### Step 2.1 — Write tests first

- [ ] Create `tests/test_kill_chain.py`:

```python
"""Tests for kill chain phase tagging."""
import pytest

from enforcement.phases import KillChainPhase, TOOL_PHASE_MAP, get_tool_phase


class TestKillChainPhase:
    def test_phase_ordering(self):
        assert KillChainPhase.RECON < KillChainPhase.ENUMERATION
        assert KillChainPhase.ENUMERATION < KillChainPhase.EXPLOITATION
        assert KillChainPhase.EXPLOITATION < KillChainPhase.POST_EXPLOITATION
        assert KillChainPhase.POST_EXPLOITATION < KillChainPhase.LATERAL_MOVEMENT
        assert KillChainPhase.LATERAL_MOVEMENT < KillChainPhase.PERSISTENCE
        assert KillChainPhase.PERSISTENCE < KillChainPhase.EXFIL

    def test_phase_values(self):
        assert KillChainPhase.RECON.value == 0
        assert KillChainPhase.EXFIL.value == 6

    def test_phase_from_name(self):
        assert KillChainPhase["EXPLOITATION"] == KillChainPhase.EXPLOITATION


class TestToolPhaseMap:
    def test_nmap_scan_is_recon(self):
        assert TOOL_PHASE_MAP["nmap_scan"] == KillChainPhase.RECON

    def test_nmap_vuln_is_enumeration(self):
        assert TOOL_PHASE_MAP["nmap_vuln_scan"] == KillChainPhase.ENUMERATION

    def test_nikto_is_enumeration(self):
        assert TOOL_PHASE_MAP["nikto_scan"] == KillChainPhase.ENUMERATION

    def test_wifi_deauth_is_exploitation(self):
        assert TOOL_PHASE_MAP["wifi_deauth"] == KillChainPhase.EXPLOITATION

    def test_evil_portal_is_exploitation(self):
        assert TOOL_PHASE_MAP["wifi_evil_portal"] == KillChainPhase.EXPLOITATION

    def test_shell_exec_is_exploitation(self):
        assert TOOL_PHASE_MAP["shell_exec"] == KillChainPhase.EXPLOITATION

    def test_rf_scan_is_recon(self):
        assert TOOL_PHASE_MAP["rf_scan"] == KillChainPhase.RECON

    def test_rf_replay_is_exploitation(self):
        assert TOOL_PHASE_MAP["rf_replay"] == KillChainPhase.EXPLOITATION

    def test_hashcat_crack_is_exploitation(self):
        assert TOOL_PHASE_MAP["hashcat_crack"] == KillChainPhase.EXPLOITATION

    def test_all_engagement_config_tools_are_mapped(self):
        """Every tool in engagement-config.json tool_risk must be in TOOL_PHASE_MAP."""
        import json
        with open("config/engagement-config.json") as f:
            config = json.load(f)
        tool_risk = config.get("tool_risk", {})
        for tool_name in tool_risk:
            assert tool_name in TOOL_PHASE_MAP, f"{tool_name} missing from TOOL_PHASE_MAP"


class TestGetToolPhase:
    def test_known_tool(self):
        assert get_tool_phase("nmap_scan") == KillChainPhase.RECON

    def test_unknown_tool_returns_none(self):
        assert get_tool_phase("unknown_tool") is None

    def test_phase_comparison_for_ceiling(self):
        """Verify phase ceiling logic works: tool phase <= max_phase."""
        max_phase = KillChainPhase.ENUMERATION
        assert get_tool_phase("nmap_scan") <= max_phase  # RECON <= ENUM
        assert get_tool_phase("nmap_vuln_scan") <= max_phase  # ENUM <= ENUM
        assert get_tool_phase("wifi_deauth") > max_phase  # EXPLOIT > ENUM
```

- [ ] Run tests — confirm they fail:

```bash
python3 -m pytest tests/test_kill_chain.py --tb=short 2>&1 | tail -5
# Expected: ERROR — ModuleNotFoundError: No module named 'enforcement.phases'
```

### Step 2.2 — Implement KillChainPhase

- [ ] Create `enforcement/phases.py`:

```python
"""Kill chain phase definitions and tool-to-phase mapping.

Maps every pentest tool action to its minimum kill chain phase.
Used by EnforcementMiddleware to enforce phase ceilings — an engagement
capped at ENUMERATION cannot invoke EXPLOITATION-phase tools.
"""
from __future__ import annotations

from enum import IntEnum
from typing import Optional


class KillChainPhase(IntEnum):
    """Simplified kill chain phases for engagement phase gating."""
    RECON = 0
    ENUMERATION = 1
    EXPLOITATION = 2
    POST_EXPLOITATION = 3
    LATERAL_MOVEMENT = 4
    PERSISTENCE = 5
    EXFIL = 6


# Maps every tool action (from engagement-config.json tool_risk + blackarch actions)
# to the minimum kill chain phase required to invoke it.
#
# Guideline:
#   RECON          — passive observation, scanning, fingerprinting
#   ENUMERATION    — active probing, vuln scanning, service interrogation
#   EXPLOITATION   — attacks, injections, credential cracking, deauth
#   POST_EXPLOIT+  — reserved for future lateral movement / persistence tools
TOOL_PHASE_MAP: dict[str, KillChainPhase] = {
    # ── PortaPack / RF (passive observation) ──
    "rf_scan": KillChainPhase.RECON,
    "rf_read_screen": KillChainPhase.RECON,
    "rf_radio_info": KillChainPhase.RECON,
    "rf_screenshot": KillChainPhase.RECON,
    "rf_capture": KillChainPhase.RECON,
    "rf_set_frequency": KillChainPhase.RECON,
    "rf_app_start": KillChainPhase.RECON,
    "rf_replay": KillChainPhase.EXPLOITATION,
    "rf_send_pocsag": KillChainPhase.EXPLOITATION,

    # ── Flipper Zero ──
    "flip_subghz_rx": KillChainPhase.RECON,
    "flip_nfc_read": KillChainPhase.RECON,
    "flip_rfid_read": KillChainPhase.RECON,
    "flip_ir_rx": KillChainPhase.RECON,
    "flip_ble_scan": KillChainPhase.RECON,
    "flip_storage_list": KillChainPhase.RECON,
    "flip_subghz_tx": KillChainPhase.EXPLOITATION,
    "flip_nfc_write": KillChainPhase.EXPLOITATION,
    "flip_rfid_write": KillChainPhase.EXPLOITATION,
    "flip_ir_tx": KillChainPhase.EXPLOITATION,
    "flip_subghz_bruteforce": KillChainPhase.EXPLOITATION,

    # ── WiFi Marauder ──
    "wifi_scan_aps": KillChainPhase.RECON,
    "wifi_scan_stations": KillChainPhase.RECON,
    "wifi_sniff_pmkid": KillChainPhase.ENUMERATION,
    "wifi_deauth": KillChainPhase.EXPLOITATION,
    "wifi_beacon_spam": KillChainPhase.EXPLOITATION,
    "wifi_evil_portal": KillChainPhase.EXPLOITATION,
    "wifi_karma": KillChainPhase.EXPLOITATION,

    # ── BlackArch / Network ──
    "nmap_scan": KillChainPhase.RECON,
    "nmap_vuln_scan": KillChainPhase.ENUMERATION,
    "aircrack_monitor": KillChainPhase.RECON,
    "aircrack_capture": KillChainPhase.RECON,
    "aircrack_crack": KillChainPhase.EXPLOITATION,
    "bettercap_recon": KillChainPhase.RECON,
    "bettercap_mitm": KillChainPhase.EXPLOITATION,
    "shell_exec": KillChainPhase.EXPLOITATION,

    # ── BlackArch curated actions (dispatch names) ──
    "nikto_scan": KillChainPhase.ENUMERATION,
    "gobuster_scan": KillChainPhase.ENUMERATION,
    "hashcat_crack": KillChainPhase.EXPLOITATION,
    "tshark_capture": KillChainPhase.RECON,
    "airodump_scan": KillChainPhase.RECON,
    "airmon_start": KillChainPhase.RECON,
    "airmon_stop": KillChainPhase.RECON,
}


def get_tool_phase(tool_name: str) -> Optional[KillChainPhase]:
    """Get the kill chain phase for a tool action.

    Returns None if the tool is not in the phase map (i.e., it's not a
    pentest tool and phase gating doesn't apply).
    """
    return TOOL_PHASE_MAP.get(tool_name)
```

- [ ] Run tests — confirm all pass:

```bash
python3 -m pytest tests/test_kill_chain.py --tb=short -q
# Expected: ~14 passed
```

- [ ] Run full suite:

```bash
python3 -m pytest tests/ --tb=short -q
# Expected: all previous + new = green
```

- [ ] Commit:

```bash
git add enforcement/phases.py tests/test_kill_chain.py
git commit -m "feat: KillChainPhase enum and tool-to-phase mapping"
```

---

## Task 3: RateLimiter

**Create:** `enforcement/rate_limiter.py`
**Test:** `tests/test_rate_limiter.py`

### Step 3.1 — Write tests first

- [ ] Create `tests/test_rate_limiter.py`:

```python
"""Tests for RateLimiter — sliding window rate limiting for tool calls."""
import time
import pytest

from enforcement.rate_limiter import RateLimiter


class TestBasicRateLimiting:
    def test_allows_under_limit(self):
        rl = RateLimiter({"deauth": {"max": 5, "window_seconds": 3600}})
        allowed, reason = rl.check("deauth")
        assert allowed is True
        assert reason is None

    def test_blocks_at_limit(self):
        rl = RateLimiter({"deauth": {"max": 2, "window_seconds": 3600}})
        rl.check("deauth")
        rl.check("deauth")
        allowed, reason = rl.check("deauth")
        assert allowed is False
        assert "deauth" in reason
        assert "2" in reason

    def test_unlisted_action_always_allowed(self):
        rl = RateLimiter({"deauth": {"max": 1, "window_seconds": 3600}})
        allowed, reason = rl.check("nmap_scan")
        assert allowed is True

    def test_empty_limits_allows_all(self):
        rl = RateLimiter({})
        allowed, reason = rl.check("anything")
        assert allowed is True


class TestSlidingWindow:
    def test_window_expiry(self):
        rl = RateLimiter({"test_action": {"max": 1, "window_seconds": 0.1}})
        rl.check("test_action")
        # Should be blocked immediately
        allowed, _ = rl.check("test_action")
        assert allowed is False
        # Wait for window to expire
        time.sleep(0.15)
        allowed, _ = rl.check("test_action")
        assert allowed is True

    def test_sliding_window_partial_expiry(self):
        rl = RateLimiter({"action": {"max": 2, "window_seconds": 0.2}})
        rl.check("action")  # t=0
        time.sleep(0.12)
        rl.check("action")  # t=0.12
        # Both within window — next should fail
        allowed, _ = rl.check("action")
        assert allowed is False
        # Wait for first call to expire
        time.sleep(0.12)
        # Now only the t=0.12 call is in the window — should succeed
        allowed, _ = rl.check("action")
        assert allowed is True


class TestMultipleActions:
    def test_independent_counters(self):
        rl = RateLimiter({
            "action_a": {"max": 1, "window_seconds": 3600},
            "action_b": {"max": 1, "window_seconds": 3600},
        })
        rl.check("action_a")
        # action_b should still be allowed
        allowed, _ = rl.check("action_b")
        assert allowed is True

    def test_different_limits(self):
        rl = RateLimiter({
            "fast": {"max": 10, "window_seconds": 3600},
            "slow": {"max": 1, "window_seconds": 3600},
        })
        for _ in range(10):
            rl.check("fast")
        # fast exhausted
        allowed_fast, _ = rl.check("fast")
        assert allowed_fast is False
        # slow still has 1
        allowed_slow, _ = rl.check("slow")
        assert allowed_slow is True


class TestReset:
    def test_reset_clears_counts(self):
        rl = RateLimiter({"action": {"max": 1, "window_seconds": 3600}})
        rl.check("action")
        allowed, _ = rl.check("action")
        assert allowed is False
        rl.reset()
        allowed, _ = rl.check("action")
        assert allowed is True

    def test_reset_single_action(self):
        rl = RateLimiter({
            "a": {"max": 1, "window_seconds": 3600},
            "b": {"max": 1, "window_seconds": 3600},
        })
        rl.check("a")
        rl.check("b")
        rl.reset("a")
        allowed_a, _ = rl.check("a")
        allowed_b, _ = rl.check("b")
        assert allowed_a is True
        assert allowed_b is False
```

- [ ] Run tests — confirm they fail:

```bash
python3 -m pytest tests/test_rate_limiter.py --tb=short 2>&1 | tail -5
# Expected: ERROR — ModuleNotFoundError
```

### Step 3.2 — Implement RateLimiter

- [ ] Create `enforcement/rate_limiter.py`:

```python
"""Sliding-window rate limiter for tool call frequency enforcement.

In-memory only — resets on process restart (by design: rate limits are
per-engagement, not persistent). For persistent audit, use EngagementStore.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Optional


class RateLimiter:
    """Sliding-window rate limiter for pentest tool calls.

    Args:
        limits: Dict mapping action names to limit configs.
                Example: {"deauth": {"max": 10, "window_seconds": 3600}}
                Actions not in this dict are unlimited.
    """

    def __init__(self, limits: dict):
        self._limits = limits
        # action_name -> list of timestamps (monotonic)
        self._windows: dict[str, list[float]] = defaultdict(list)

    def check(self, action: str) -> tuple[bool, Optional[str]]:
        """Check if an action is within its rate limit.

        Returns:
            (True, None) if allowed.
            (False, reason_string) if rate-limited.
        """
        limit_cfg = self._limits.get(action)
        if limit_cfg is None:
            return True, None

        max_calls = limit_cfg["max"]
        window_secs = limit_cfg["window_seconds"]
        now = time.monotonic()

        # Prune expired entries
        cutoff = now - window_secs
        timestamps = self._windows[action]
        self._windows[action] = [t for t in timestamps if t > cutoff]

        if len(self._windows[action]) >= max_calls:
            return False, (
                f"Rate limit exceeded for '{action}': "
                f"{max_calls} calls per {window_secs}s window"
            )

        # Record this call
        self._windows[action].append(now)
        return True, None

    def reset(self, action: Optional[str] = None):
        """Reset rate limit counters.

        Args:
            action: If provided, reset only that action. Otherwise reset all.
        """
        if action:
            self._windows.pop(action, None)
        else:
            self._windows.clear()
```

- [ ] Run tests — confirm all pass:

```bash
python3 -m pytest tests/test_rate_limiter.py --tb=short -q
# Expected: ~13 passed
```

- [ ] Run full suite:

```bash
python3 -m pytest tests/ --tb=short -q
```

- [ ] Commit:

```bash
git add enforcement/rate_limiter.py tests/test_rate_limiter.py
git commit -m "feat: sliding-window RateLimiter for tool call enforcement"
```

---

## Task 4: EnforcementMiddleware

**Create:** `graph/middleware/enforcement.py`
**Test:** `tests/test_enforcement_middleware.py`

This is the core of Phase 1 — it wires ScopeValidator, KillChainPhase, and RateLimiter into the agent middleware chain.

### Step 4.1 — Write tests first

- [ ] Create `tests/test_enforcement_middleware.py`:

```python
"""Tests for EnforcementMiddleware — the central enforcement gate.

All tests mock the engagement_manager and handler to avoid needing
a real LangGraph agent. The middleware operates on request.tool_call
dicts, identical to AuditMiddleware's pattern.
"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from graph.middleware.enforcement import EnforcementMiddleware
from enforcement.scope import ScopeValidator
from enforcement.phases import KillChainPhase
from enforcement.rate_limiter import RateLimiter


def _make_request(tool_name: str, args: dict = None):
    """Build a mock middleware request with tool_call dict."""
    req = MagicMock()
    req.tool_call = {"name": tool_name, "args": args or {}}
    return req


def _make_engagement_manager(active=True, mode_name="ACTIVE", mode_value=1):
    """Build a mock EngagementManager."""
    mgr = MagicMock()
    mgr.active_engagement = {"name": "test"} if active else None
    mgr.mode = MagicMock()
    mgr.mode.name = mode_name
    mgr.mode.value = mode_value
    mgr.is_allowed = MagicMock(return_value=True)
    return mgr


class TestNonPentestToolsPassThrough:
    """Non-pentest tools (cve_search, browser, etc.) should always pass."""

    @pytest.mark.asyncio
    async def test_cve_search_passes(self):
        mgr = _make_engagement_manager(active=False)
        mw = EnforcementMiddleware(mgr)
        req = _make_request("cve_search", {"query": "log4j"})
        handler = AsyncMock(return_value="results")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once_with(req)
        assert result == "results"

    @pytest.mark.asyncio
    async def test_browser_passes(self):
        mgr = _make_engagement_manager(active=False)
        mw = EnforcementMiddleware(mgr)
        req = _make_request("browser", {"action": "open", "url": "https://example.com"})
        handler = AsyncMock(return_value="ok")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()
        assert result == "ok"


class TestEngagementRequired:
    """Pentest tools require an active engagement."""

    @pytest.mark.asyncio
    async def test_nmap_blocked_without_engagement(self):
        mgr = _make_engagement_manager(active=False)
        mw = EnforcementMiddleware(mgr)
        req = _make_request("nmap_scan", {"target": "192.168.1.1"})
        handler = AsyncMock()
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_not_awaited()
        assert "BLOCKED" in result
        assert "engagement" in result.lower()

    @pytest.mark.asyncio
    async def test_engagement_tool_itself_is_exempt(self):
        """The engagement tool (start/end/status) must work without an active engagement."""
        mgr = _make_engagement_manager(active=False)
        mw = EnforcementMiddleware(mgr)
        req = _make_request("engagement", {"action": "start", "name": "test"})
        handler = AsyncMock(return_value="started")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()
        assert result == "started"


class TestModeEnforcement:
    """Engagement mode (passive/active/redteam) is enforced."""

    @pytest.mark.asyncio
    async def test_mode_allows_tool(self):
        mgr = _make_engagement_manager()
        mgr.is_allowed.return_value = True
        mw = EnforcementMiddleware(mgr)
        req = _make_request("nmap_scan", {"target": "10.0.0.1"})
        handler = AsyncMock(return_value="scan results")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()
        assert result == "scan results"

    @pytest.mark.asyncio
    async def test_mode_blocks_tool(self):
        mgr = _make_engagement_manager()
        mgr.is_allowed.return_value = False
        mgr._tool_risk = {"wifi_deauth": 2}
        mw = EnforcementMiddleware(mgr)
        req = _make_request("wifi_deauth", {})
        handler = AsyncMock()
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_not_awaited()
        assert "BLOCKED" in result
        assert "mode" in result.lower()


class TestScopeEnforcement:
    @pytest.mark.asyncio
    async def test_target_in_scope_passes(self):
        mgr = _make_engagement_manager()
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        mw = EnforcementMiddleware(mgr, scope_validator=sv)
        req = _make_request("nmap_scan", {"target": "192.168.4.50"})
        handler = AsyncMock(return_value="scan output")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()
        assert result == "scan output"

    @pytest.mark.asyncio
    async def test_target_out_of_scope_blocked(self):
        mgr = _make_engagement_manager()
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        mw = EnforcementMiddleware(mgr, scope_validator=sv)
        req = _make_request("nmap_scan", {"target": "10.0.0.1"})
        handler = AsyncMock()
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_not_awaited()
        assert "BLOCKED" in result
        assert "scope" in result.lower()

    @pytest.mark.asyncio
    async def test_tool_without_target_skips_scope_check(self):
        """Tools like hashcat don't have remote targets — scope check is skipped."""
        mgr = _make_engagement_manager()
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        mw = EnforcementMiddleware(mgr, scope_validator=sv)
        req = _make_request("hashcat_crack", {"hash_file": "/tmp/hashes"})
        handler = AsyncMock(return_value="cracked")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()


class TestPhaseEnforcement:
    @pytest.mark.asyncio
    async def test_recon_tool_under_enum_ceiling(self):
        mgr = _make_engagement_manager()
        mw = EnforcementMiddleware(mgr, max_phase=KillChainPhase.ENUMERATION)
        req = _make_request("nmap_scan", {"target": "10.0.0.1"})
        handler = AsyncMock(return_value="scan")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_exploit_tool_blocked_by_enum_ceiling(self):
        mgr = _make_engagement_manager()
        mw = EnforcementMiddleware(mgr, max_phase=KillChainPhase.ENUMERATION)
        req = _make_request("wifi_deauth", {})
        handler = AsyncMock()
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_not_awaited()
        assert "BLOCKED" in result
        assert "phase" in result.lower()

    @pytest.mark.asyncio
    async def test_no_phase_ceiling_allows_all(self):
        mgr = _make_engagement_manager()
        mw = EnforcementMiddleware(mgr)  # no max_phase
        req = _make_request("wifi_deauth", {})
        handler = AsyncMock(return_value="deauthed")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()


class TestRateLimitEnforcement:
    @pytest.mark.asyncio
    async def test_under_limit_passes(self):
        mgr = _make_engagement_manager()
        rl = RateLimiter({"nmap_scan": {"max": 10, "window_seconds": 3600}})
        mw = EnforcementMiddleware(mgr, rate_limiter=rl)
        req = _make_request("nmap_scan", {"target": "10.0.0.1"})
        handler = AsyncMock(return_value="result")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_over_limit_blocked(self):
        mgr = _make_engagement_manager()
        rl = RateLimiter({"nmap_scan": {"max": 1, "window_seconds": 3600}})
        mw = EnforcementMiddleware(mgr, rate_limiter=rl)
        handler = AsyncMock(return_value="result")

        # First call passes
        req1 = _make_request("nmap_scan", {"target": "10.0.0.1"})
        await mw.awrap_tool_call(req1, handler)
        # Second call blocked
        req2 = _make_request("nmap_scan", {"target": "10.0.0.2"})
        result = await mw.awrap_tool_call(req2, handler)
        assert "BLOCKED" in result
        assert "rate" in result.lower()


class TestSyncMirror:
    """wrap_tool_call (sync) should mirror awrap_tool_call behavior."""

    def test_sync_passthrough(self):
        mgr = _make_engagement_manager(active=False)
        mw = EnforcementMiddleware(mgr)
        req = _make_request("cve_search", {"query": "test"})
        handler = MagicMock(return_value="results")
        result = mw.wrap_tool_call(req, handler)
        handler.assert_called_once_with(req)
        assert result == "results"

    def test_sync_blocks_pentest_without_engagement(self):
        mgr = _make_engagement_manager(active=False)
        mw = EnforcementMiddleware(mgr)
        req = _make_request("nmap_scan", {"target": "1.2.3.4"})
        handler = MagicMock()
        result = mw.wrap_tool_call(req, handler)
        handler.assert_not_called()
        assert "BLOCKED" in result


class TestEnforcementOrder:
    """Enforcement checks run in the correct order: engagement → mode → scope → phase → rate."""

    @pytest.mark.asyncio
    async def test_mode_checked_before_scope(self):
        """If mode blocks, scope is never checked."""
        mgr = _make_engagement_manager()
        mgr.is_allowed.return_value = False
        mgr._tool_risk = {"nmap_scan": 1}
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        mw = EnforcementMiddleware(mgr, scope_validator=sv)
        req = _make_request("nmap_scan", {"target": "192.168.4.1"})
        handler = AsyncMock()
        result = await mw.awrap_tool_call(req, handler)
        assert "BLOCKED" in result
        assert "mode" in result.lower()
```

- [ ] Run tests — confirm they fail:

```bash
python3 -m pytest tests/test_enforcement_middleware.py --tb=short 2>&1 | tail -5
# Expected: ERROR — ModuleNotFoundError
```

### Step 4.2 — Implement EnforcementMiddleware

- [ ] Create `graph/middleware/enforcement.py`:

```python
"""EnforcementMiddleware — hard enforcement gate for pentest tool calls.

Checks (in order):
  1. Is this a pentest tool? If not, pass through.
  2. Is the engagement tool itself? If so, exempt (must be able to start/end).
  3. Is there an active engagement? Block if not.
  4. Is the tool permitted under the current engagement mode? Block if not.
  5. Is the target within scope? Block if not.
  6. Is the tool within the kill chain phase ceiling? Block if not.
  7. Is the tool within rate limits? Block if not.

On block: returns a structured error string (never calls handler).
On pass: calls handler(request) and returns the result.

Must be placed FIRST in the middleware chain (before AuditMiddleware)
so that blocked calls are still logged by audit but never executed.
"""
from __future__ import annotations

import logging
from typing import Optional

from langchain.agents.middleware import AgentMiddleware

from enforcement.phases import KillChainPhase, get_tool_phase
from enforcement.rate_limiter import RateLimiter
from enforcement.scope import ScopeValidator
from guardrails import _PENTEST_TOOL_PREFIXES

logger = logging.getLogger(__name__)

# The engagement tool itself must be exempt from the "active engagement required"
# check — otherwise you can't start or query an engagement.
_EXEMPT_TOOLS = {"engagement", "device_manager"}


class EnforcementMiddleware(AgentMiddleware):
    """Hard enforcement gate for pentest tool calls.

    Args:
        engagement_manager: An EngagementManager instance (from tools.engagement).
        scope_validator: Optional ScopeValidator for target scope checks.
        rate_limiter: Optional RateLimiter for call frequency limits.
        max_phase: Optional KillChainPhase ceiling — tools above this phase are blocked.
    """

    def __init__(
        self,
        engagement_manager,
        scope_validator: Optional[ScopeValidator] = None,
        rate_limiter: Optional[RateLimiter] = None,
        max_phase: Optional[KillChainPhase] = None,
    ):
        super().__init__()
        self._engagement_manager = engagement_manager
        self._scope_validator = scope_validator
        self._rate_limiter = rate_limiter
        self._max_phase = max_phase

    def wrap_tool_call(self, request, handler):
        """Sync enforcement gate."""
        blocked = self._enforce(request)
        if blocked:
            return blocked
        return handler(request)

    async def awrap_tool_call(self, request, handler):
        """Async enforcement gate."""
        blocked = self._enforce(request)
        if blocked:
            return blocked
        return await handler(request)

    def _enforce(self, request) -> Optional[str]:
        """Run all enforcement checks.

        Returns None if all checks pass (caller should proceed to handler).
        Returns a BLOCKED error string if any check fails.
        """
        tool_name = request.tool_call.get("name", "unknown")
        args = request.tool_call.get("args", {})

        # ── Check 1: Is this a pentest tool? ──
        if not self._is_pentest_tool(tool_name):
            return None  # pass through

        # ── Check 2: Is this an exempt tool (engagement, device_manager)? ──
        if tool_name in _EXEMPT_TOOLS:
            return None  # always allowed

        # For tool actions dispatched through a parent tool (e.g., blackarch.nmap_scan),
        # check the action name from args if the top-level tool name is a prefix.
        action = args.get("action", tool_name)

        # ── Check 3: Active engagement required ──
        mgr = self._engagement_manager
        if mgr is None or mgr.active_engagement is None:
            logger.warning("BLOCKED %s: no active engagement", tool_name)
            return (
                f"[BLOCKED] Tool '{tool_name}' requires an active engagement. "
                f"Use the engagement tool to start one first."
            )

        # ── Check 4: Mode enforcement ──
        if not mgr.is_allowed(action):
            risk = getattr(mgr, "_tool_risk", {}).get(action, "?")
            logger.warning(
                "BLOCKED %s: mode %s insufficient (risk=%s)", action, mgr.mode.name, risk
            )
            return (
                f"[BLOCKED] Tool '{action}' denied by mode enforcement. "
                f"Current mode: {mgr.mode.name} (level={mgr.mode.value}), "
                f"tool risk level: {risk}. Escalate mode with engagement set_mode."
            )

        # ── Check 5: Scope enforcement ──
        if self._scope_validator:
            target = self._scope_validator.extract_target(action, args)
            if target and not self._scope_validator.is_in_scope(target):
                logger.warning("BLOCKED %s: target '%s' out of scope", action, target)
                return (
                    f"[BLOCKED] Target '{target}' is outside engagement scope. "
                    f"Tool '{action}' denied."
                )

        # ── Check 6: Phase ceiling ──
        if self._max_phase is not None:
            tool_phase = get_tool_phase(action)
            if tool_phase is not None and tool_phase > self._max_phase:
                logger.warning(
                    "BLOCKED %s: phase %s exceeds ceiling %s",
                    action, tool_phase.name, self._max_phase.name,
                )
                return (
                    f"[BLOCKED] Tool '{action}' is phase {tool_phase.name} "
                    f"but engagement ceiling is {self._max_phase.name}. "
                    f"Cannot execute {tool_phase.name}-phase tools."
                )

        # ── Check 7: Rate limiting ──
        if self._rate_limiter:
            allowed, reason = self._rate_limiter.check(action)
            if not allowed:
                logger.warning("BLOCKED %s: rate limited — %s", action, reason)
                return f"[BLOCKED] {reason}"

        return None  # all checks passed

    @staticmethod
    def _is_pentest_tool(tool_name: str) -> bool:
        """Check if a tool name belongs to the pentest domain.

        Uses the same prefix set as guardrails.py. A tool is pentest if its
        name matches a known prefix OR if the tool_name itself is in the set.
        """
        if tool_name in _PENTEST_TOOL_PREFIXES:
            return True
        prefix = tool_name.split("_")[0] if "_" in tool_name else tool_name
        return prefix in _PENTEST_TOOL_PREFIXES
```

- [ ] Run tests — confirm all pass:

```bash
python3 -m pytest tests/test_enforcement_middleware.py --tb=short -q
# Expected: ~18 passed
```

- [ ] Run full suite:

```bash
python3 -m pytest tests/ --tb=short -q
```

- [ ] Commit:

```bash
git add graph/middleware/enforcement.py tests/test_enforcement_middleware.py
git commit -m "feat: EnforcementMiddleware with mode, scope, phase, and rate limiting"
```

---

## Task 5: Wire EnforcementMiddleware into Agent Graph

**Modify:** `graph/agent.py`, `tools/lg_tools.py`, `server.py`, `tools/engagement.py`, `config/engagement-config.json`
**Test:** Existing tests must stay green + manual verification

### Step 5.1 — Add accessor for engagement_manager in lg_tools.py

- [ ] Modify `tools/lg_tools.py` — add `get_engagement_manager()` function **after** the existing `get_combined_tools()` function (which ends around line 610):

```python
# Add this function after get_combined_tools():

def get_engagement_manager():
    """Return the EngagementManager singleton (lazy-init if needed).

    Used by graph/agent.py to pass the engagement manager to
    EnforcementMiddleware.
    """
    _init_pentest_singletons()
    return _engagement
```

**Where exactly:** Find the line `def get_combined_tools(knowledge_store=None):` and its body. Add the new function right after the `return` statement of `get_combined_tools`.

### Step 5.2 — Update config/engagement-config.json

- [ ] Add three new keys to `config/engagement-config.json`. Add them after the existing `"tool_risk"` block, before the closing `}`:

Add inside the `"engagement"` object (after `"alert_channel_id": ""`):

```json
"max_phase": "exploitation",
"scope": {"type": "any"},
```

Add as a new top-level key (after `"tool_risk"` block):

```json
"rate_limits": {
    "wifi_deauth": {"max": 10, "window_seconds": 3600},
    "wifi_beacon_spam": {"max": 5, "window_seconds": 3600},
    "wifi_evil_portal": {"max": 3, "window_seconds": 3600},
    "wifi_karma": {"max": 3, "window_seconds": 3600},
    "flip_subghz_bruteforce": {"max": 5, "window_seconds": 3600},
    "shell_exec": {"max": 30, "window_seconds": 3600},
    "rf_replay": {"max": 20, "window_seconds": 3600}
}
```

The final file should look like this (showing only the structural changes):

```json
{
  "instance": { ... },
  "devices": { ... },
  "engagement": {
    "default_mode": "passive",
    "workspace_dir": "/home/deck/engagements",
    "alert_webhook": "",
    "alert_channel_id": "",
    "max_phase": "exploitation",
    "scope": {"type": "any"}
  },
  "risk_levels": { ... },
  "tool_risk": { ... },
  "rate_limits": {
    "wifi_deauth": {"max": 10, "window_seconds": 3600},
    "wifi_beacon_spam": {"max": 5, "window_seconds": 3600},
    "wifi_evil_portal": {"max": 3, "window_seconds": 3600},
    "wifi_karma": {"max": 3, "window_seconds": 3600},
    "flip_subghz_bruteforce": {"max": 5, "window_seconds": 3600},
    "shell_exec": {"max": 30, "window_seconds": 3600},
    "rf_replay": {"max": 20, "window_seconds": 3600}
  }
}
```

### Step 5.3 — Modify tools/engagement.py to accept max_phase and scope on start()

- [ ] Modify `tools/engagement.py` — add `max_phase` and `scope_config` attributes to `__init__`, update `start()`, update `_exec_start()`.

In `__init__` (around line 35), after `self.findings: list[dict] = []`, add:

```python
        self.max_phase: Optional[str] = config["engagement"].get("max_phase")
        self.scope_config: dict = config["engagement"].get("scope", {"type": "any"})
```

In `start()` method (around line 104), modify the signature and body:

```python
    def start(self, name: str, scope: str = "", mode: str = None,
              max_phase: str = None, scope_config: dict = None):
        ws = self._workspace_root / name
        ws.mkdir(parents=True, exist_ok=True)
        if mode:
            self._mode = EngagementMode[mode.upper()]
        if max_phase:
            self.max_phase = max_phase
        if scope_config:
            self.scope_config = scope_config
        self.active_engagement = {
            "name": name,
            "scope": scope,
            "mode": self._mode.name,
            "max_phase": self.max_phase,
            "scope_config": self.scope_config,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "workspace": str(ws),
        }
        self.findings = []
        (ws / "engagement.json").write_text(json.dumps(self.active_engagement, indent=2))
        logger.info("Engagement '%s' started — scope: %s, mode: %s, max_phase: %s",
                     name, scope, self._mode.name, self.max_phase)
```

In `_exec_start()` (around line 143), pass the new params:

```python
    def _exec_start(self, kwargs) -> str:
        self.start(
            kwargs.get("name", "unnamed"),
            kwargs.get("scope", ""),
            kwargs.get("mode"),
            kwargs.get("max_phase"),
            kwargs.get("scope_config"),
        )
        return f"Engagement '{kwargs.get('name')}' started in {self._mode.name} mode"
```

Also update the `parameters` property to include `max_phase`:

In the `"properties"` dict inside `parameters` (around line 58), add:

```python
                "max_phase": {
                    "type": "string",
                    "description": "Kill chain phase ceiling (recon, enumeration, exploitation)",
                    "enum": ["recon", "enumeration", "exploitation", "post_exploitation"],
                },
```

### Step 5.4 — Modify graph/agent.py to accept and wire enforcement middleware

- [ ] Modify `graph/agent.py`:

**Add import** at the top (after existing imports, around line 10):

```python
from graph.middleware.enforcement import EnforcementMiddleware
from enforcement.scope import ScopeValidator
from enforcement.phases import KillChainPhase
from enforcement.rate_limiter import RateLimiter
```

**Modify `_build_middleware()`** signature and body — add `engagement_manager` parameter:

Replace the entire `_build_middleware` function:

```python
def _build_middleware(config: LangGraphConfig, knowledge_store=None, engagement_manager=None):
    """Build the ordered middleware chain.

    EnforcementMiddleware is FIRST — blocked calls never reach the tool
    but ARE still logged by AuditMiddleware (which comes after).
    """
    middleware = []

    # Enforcement middleware — FIRST in chain
    if engagement_manager is not None:
        scope_config = getattr(engagement_manager, "scope_config", {"type": "any"})
        scope_validator = ScopeValidator(scope_config)

        max_phase_str = getattr(engagement_manager, "max_phase", None)
        max_phase = None
        if max_phase_str:
            try:
                max_phase = KillChainPhase[max_phase_str.upper()]
            except KeyError:
                pass

        # Load rate limits from engagement config
        rate_limits = getattr(engagement_manager, "_config", {}).get("rate_limits", {})
        rate_limiter = RateLimiter(rate_limits) if rate_limits else None

        middleware.append(EnforcementMiddleware(
            engagement_manager=engagement_manager,
            scope_validator=scope_validator,
            rate_limiter=rate_limiter,
            max_phase=max_phase,
        ))

    if config.knowledge_middleware and knowledge_store:
        middleware.append(KnowledgeMiddleware(
            knowledge_store,
            top_k=config.knowledge_top_k,
            search_mode=config.knowledge_search_mode,
        ))

    if config.audit_middleware:
        middleware.append(AuditMiddleware())

    if config.memory_middleware and knowledge_store:
        middleware.append(MemoryMiddleware(knowledge_store))

    middleware.append(MessageCaptureMiddleware())

    return middleware
```

**Modify `create_researcher_graph()`** to accept `engagement_manager`:

```python
def create_researcher_graph(
    config: LangGraphConfig,
    knowledge_store=None,
    include_subagents: bool = True,
    sitrep: str = "",
    engagement_manager=None,
):
```

And update the `_build_middleware` call inside it:

```python
    # Build middleware
    middleware = _build_middleware(config, knowledge_store, engagement_manager)
```

### Step 5.5 — Modify server.py to pass engagement_manager to graph

- [ ] Modify `server.py` — in `_init_langgraph_agent()` (around line 105):

**Add import** after the existing imports inside the function:

```python
    from tools.lg_tools import get_engagement_manager
```

**Before** the `_graph = create_researcher_graph(...)` call, add:

```python
    engagement_mgr = get_engagement_manager()
```

**Update** the `create_researcher_graph()` call to pass it:

```python
    _graph = create_researcher_graph(
        config=_graph_config,
        knowledge_store=store,
        include_subagents=True,
        sitrep=status_block,
        engagement_manager=engagement_mgr,
    )
```

### Step 5.6 — Verify

- [ ] Run full test suite — all existing tests MUST still pass:

```bash
python3 -m pytest tests/ --tb=short -q
# Expected: all green (244 original + new enforcement tests)
```

- [ ] Verify the engagement config is valid JSON:

```bash
python3 -c "import json; json.load(open('config/engagement-config.json')); print('valid')"
# Expected: valid
```

- [ ] Commit:

```bash
git add graph/agent.py tools/lg_tools.py server.py tools/engagement.py config/engagement-config.json
git commit -m "feat: wire EnforcementMiddleware into agent graph pipeline"
```

---

## Task 6: shell_exec Lockdown

**Modify:** `tools/blackarch.py`
**Test:** `tests/test_blackarch.py` (add new test methods)

### Step 6.1 — Write new tests first

- [ ] Add the following test class to `tests/test_blackarch.py` at the end of the file:

```python
class TestShellExecLockdown:
    """shell_exec deny-by-default + force override."""

    @pytest.mark.asyncio
    async def test_unknown_command_blocked(self, tool):
        """Commands not in _SAFE_COMMANDS should be blocked (not warned)."""
        result = await tool.shell_exec("custom_tool --flag")
        assert "Blocked" in result or "not in the allow list" in result

    @pytest.mark.asyncio
    async def test_safe_command_allowed(self, tool):
        """Commands in _SAFE_COMMANDS should still work."""
        with patch("tools.blackarch.asyncio.create_subprocess_exec") as mock_proc:
            proc = AsyncMock()
            proc.communicate.return_value = (b"output", b"")
            proc.returncode = 0
            mock_proc.return_value = proc
            result = await tool.shell_exec("nmap -sV 10.0.0.1")
            assert "output" in result

    @pytest.mark.asyncio
    async def test_force_without_redteam_blocked(self, tool):
        """force=True without REDTEAM mode should still block unknown commands."""
        result = await tool.shell_exec("custom_tool --flag", force=True)
        assert "Blocked" in result or "REDTEAM" in result

    @pytest.mark.asyncio
    async def test_force_with_redteam_allowed(self, tool):
        """force=True with REDTEAM mode should allow unknown commands."""
        tool._engagement_mode = 2  # REDTEAM
        with patch("tools.blackarch.asyncio.create_subprocess_exec") as mock_proc:
            proc = AsyncMock()
            proc.communicate.return_value = (b"forced output", b"")
            proc.returncode = 0
            mock_proc.return_value = proc
            result = await tool.shell_exec("custom_tool --flag", force=True)
            assert "forced output" in result

    @pytest.mark.asyncio
    async def test_blocked_commands_still_blocked_with_force(self, tool):
        """_BLOCKED_COMMANDS should be blocked even with force=True + REDTEAM."""
        tool._engagement_mode = 2
        result = await tool.shell_exec("rm -rf /", force=True)
        assert "Blocked" in result
```

- [ ] Run new tests — some will fail because the lockdown isn't implemented yet:

```bash
python3 -m pytest tests/test_blackarch.py::TestShellExecLockdown --tb=short -q
# Expected: some failures (unknown command still allowed, force param doesn't exist)
```

### Step 6.2 — Implement shell_exec lockdown

- [ ] Modify `tools/blackarch.py`:

**Add `_engagement_mode` attribute** to `BlackArchTool.__init__()` (around line 68):

After `self._workspace.mkdir(parents=True, exist_ok=True)`, add:

```python
        self._engagement_mode: int = 0  # Default PASSIVE; set externally
```

**Replace the `shell_exec` method** (around line 174-192) with the locked-down version:

```python
    async def shell_exec(self, command: str, timeout: int = 120, force: bool = False) -> str:
        """Execute a shell command with deny-by-default filtering.

        Only commands in _SAFE_COMMANDS are allowed. Unknown commands are
        BLOCKED unless force=True AND engagement mode is REDTEAM (2).
        Commands in _BLOCKED_COMMANDS are always denied regardless of force.
        """
        parts = shlex.split(command)
        if not parts:
            return "Empty command"
        base_cmd = Path(parts[0]).name

        # Hard deny list — never allowed, even with force
        if base_cmd in _BLOCKED_COMMANDS:
            return f"Blocked: '{base_cmd}' is on the deny list for safety"

        # Allow list — known-safe security tools
        if base_cmd in _SAFE_COMMANDS:
            return await self._run(*parts, timeout=timeout)

        # Unknown command — deny by default
        if force and self._engagement_mode >= 2:  # REDTEAM
            logger.warning("shell_exec: FORCE override for '%s' in REDTEAM mode", base_cmd)
            return await self._run(*parts, timeout=timeout)

        if force:
            return (
                f"Blocked: '{base_cmd}' is not in the allow list. "
                f"force=True requires REDTEAM mode (current mode level: {self._engagement_mode})"
            )

        return f"Blocked: '{base_cmd}' is not in the allow list. Use a curated action or add to _SAFE_COMMANDS."
```

**Update the `execute()` dispatch** for `shell_exec` (around line 105) to pass `force`:

Find the `shell_exec` entry in the `dispatch` dict and update it:

```python
            "shell_exec": lambda: self.shell_exec(
                kwargs.get("command", ""), kwargs.get("timeout", 120),
                kwargs.get("force", False),
            ),
```

**Update the `parameters` property** to include `force`:

In the `"properties"` dict, add:

```python
                "force": {
                    "type": "boolean",
                    "description": "Force execution of unrecognized command (requires REDTEAM mode)",
                },
```

**Wire engagement mode** — in `tools/lg_tools.py` `_init_pentest_singletons()`, after `_blackarch._target_store = _target_store`, add:

```python
    # Wire engagement mode to blackarch for shell_exec force override
    _blackarch._engagement_manager = _engagement
```

Then update `BlackArchTool.shell_exec` to read from the manager if available:

Actually, simpler: modify `shell_exec` to check `self._engagement_mode` which is already set. We just need `_init_pentest_singletons` to set it. But since mode changes dynamically, use a property. **Instead**, modify the `force` check in `shell_exec`:

Replace the force check line with:

```python
        # Resolve current engagement mode
        eng_mode = self._engagement_mode
        if hasattr(self, '_engagement_manager') and self._engagement_manager:
            eng_mode = self._engagement_manager.mode.value
```

Then use `eng_mode` instead of `self._engagement_mode` in the force checks:

```python
        if force and eng_mode >= 2:  # REDTEAM
            ...
        if force:
            return (
                f"Blocked: '{base_cmd}' is not in the allow list. "
                f"force=True requires REDTEAM mode (current mode level: {eng_mode})"
            )
```

### Step 6.3 — Verify

- [ ] Run blackarch tests:

```bash
python3 -m pytest tests/test_blackarch.py --tb=short -q
# Expected: all pass including new lockdown tests
```

- [ ] Run full suite:

```bash
python3 -m pytest tests/ --tb=short -q
```

- [ ] Commit:

```bash
git add tools/blackarch.py tests/test_blackarch.py tools/lg_tools.py
git commit -m "feat: shell_exec deny-by-default lockdown with REDTEAM force override"
```

---

## Task 7: Engagement Audit Store (SQLite)

**Create:** `knowledge/engagement_schema.sql`, `knowledge/engagement_store.py`
**Test:** `tests/test_engagement_store.py`
**Modify:** `tools/engagement.py`, `graph/middleware/enforcement.py`

### Step 7.1 — Write the schema

- [ ] Create `knowledge/engagement_schema.sql`:

```sql
-- protoPen engagement audit trail schema
-- Persistent structured logging for all engagement operations

-- Engagements: top-level engagement records
CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    scope_json TEXT,
    mode TEXT NOT NULL,
    max_phase TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    outcome TEXT
);

CREATE INDEX IF NOT EXISTS idx_engagements_name ON engagements(name);
CREATE INDEX IF NOT EXISTS idx_engagements_started ON engagements(started_at);

-- Findings: vulnerabilities and observations discovered during engagements
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    target_ip TEXT,
    target_mac TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

-- Tool calls: every tool invocation (pass or block) during an engagement
CREATE TABLE IF NOT EXISTS tool_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL,
    tool_name TEXT NOT NULL,
    action TEXT,
    args_json TEXT,
    result_summary TEXT,
    success INTEGER NOT NULL DEFAULT 1,
    blocked INTEGER NOT NULL DEFAULT 0,
    block_reason TEXT,
    duration_ms INTEGER,
    phase TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tool_calls_engagement ON tool_calls(engagement_id);
CREATE INDEX IF NOT EXISTS idx_tool_calls_tool ON tool_calls(tool_name);
CREATE INDEX IF NOT EXISTS idx_tool_calls_created ON tool_calls(created_at);

-- Phase transitions: audit trail of kill chain phase changes
CREATE TABLE IF NOT EXISTS phase_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    from_phase TEXT,
    to_phase TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_phase_transitions_engagement ON phase_transitions(engagement_id);

-- Approval log: future HITL approval gate audit trail
CREATE TABLE IF NOT EXISTS approval_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target TEXT,
    evidence TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    channel TEXT,
    responded_at TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approval_engagement ON approval_log(engagement_id);
CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_log(status);
```

### Step 7.2 — Write tests

- [ ] Create `tests/test_engagement_store.py`:

```python
"""Tests for EngagementStore — SQLite audit trail for engagements."""
import json
import pytest

from knowledge.engagement_store import EngagementStore


@pytest.fixture
def store(tmp_path):
    db_path = str(tmp_path / "test_engagements.db")
    return EngagementStore(db_path=db_path)


class TestEngagementLifecycle:
    def test_create_engagement(self, store):
        eid = store.create_engagement(
            name="test-engagement",
            scope_json=json.dumps({"type": "cidr", "targets": ["192.168.4.0/24"]}),
            mode="ACTIVE",
            max_phase="exploitation",
        )
        assert eid > 0

    def test_end_engagement(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="PASSIVE")
        store.end_engagement(eid, outcome="completed")
        eng = store.get_engagement(eid)
        assert eng["ended_at"] is not None
        assert eng["outcome"] == "completed"

    def test_get_engagement(self, store):
        eid = store.create_engagement(name="my-eng", scope_json="{}", mode="REDTEAM", max_phase="recon")
        eng = store.get_engagement(eid)
        assert eng["name"] == "my-eng"
        assert eng["mode"] == "REDTEAM"
        assert eng["max_phase"] == "recon"

    def test_get_nonexistent_engagement(self, store):
        assert store.get_engagement(999) is None


class TestFindings:
    def test_log_finding(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="ACTIVE")
        fid = store.log_finding(
            engagement_id=eid,
            severity="high",
            category="wifi",
            title="Open AP detected",
            detail="SSID 'FreeWiFi' no encryption",
            target_ip="192.168.4.1",
        )
        assert fid > 0

    def test_query_findings_by_engagement(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="ACTIVE")
        store.log_finding(eid, "high", "wifi", "Finding 1", "detail 1")
        store.log_finding(eid, "low", "network", "Finding 2", "detail 2")
        findings = store.query_findings(engagement_id=eid)
        assert len(findings) == 2

    def test_query_findings_by_severity(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="ACTIVE")
        store.log_finding(eid, "critical", "wifi", "Critical", "")
        store.log_finding(eid, "low", "rf", "Low", "")
        findings = store.query_findings(engagement_id=eid, severity="critical")
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"


class TestToolCalls:
    def test_log_tool_call(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="ACTIVE")
        tcid = store.log_tool_call(
            engagement_id=eid,
            tool_name="blackarch",
            action="nmap_scan",
            args_json=json.dumps({"target": "192.168.4.1"}),
            result_summary="scan complete",
            success=True,
            duration_ms=1500,
            phase="RECON",
        )
        assert tcid > 0

    def test_log_blocked_tool_call(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="PASSIVE")
        tcid = store.log_tool_call(
            engagement_id=eid,
            tool_name="blackarch",
            action="wifi_deauth",
            args_json="{}",
            result_summary="",
            success=False,
            blocked=True,
            block_reason="mode enforcement",
            duration_ms=0,
            phase="EXPLOITATION",
        )
        assert tcid > 0

    def test_query_tool_calls(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="ACTIVE")
        store.log_tool_call(eid, "blackarch", "nmap_scan", "{}", "ok", True, duration_ms=100, phase="RECON")
        store.log_tool_call(eid, "blackarch", "nikto_scan", "{}", "ok", True, duration_ms=200, phase="ENUMERATION")
        calls = store.query_tool_calls(engagement_id=eid)
        assert len(calls) == 2

    def test_query_tool_calls_by_tool(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="ACTIVE")
        store.log_tool_call(eid, "blackarch", "nmap_scan", "{}", "ok", True, duration_ms=100, phase="RECON")
        store.log_tool_call(eid, "marauder", "scan", "{}", "ok", True, duration_ms=50, phase="RECON")
        calls = store.query_tool_calls(engagement_id=eid, tool_name="blackarch")
        assert len(calls) == 1


class TestPhaseTransitions:
    def test_log_phase_transition(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="ACTIVE")
        tid = store.log_phase_transition(eid, from_phase="RECON", to_phase="ENUMERATION", reason="manual escalation")
        assert tid > 0


class TestEngagementSummary:
    def test_get_summary(self, store):
        eid = store.create_engagement(name="summary-test", scope_json="{}", mode="ACTIVE")
        store.log_finding(eid, "high", "wifi", "F1", "d1")
        store.log_finding(eid, "low", "rf", "F2", "d2")
        store.log_tool_call(eid, "blackarch", "nmap_scan", "{}", "ok", True, duration_ms=100, phase="RECON")
        store.log_tool_call(eid, "blackarch", "deauth", "{}", "", False, blocked=True,
                            block_reason="mode", duration_ms=0, phase="EXPLOITATION")
        summary = store.get_engagement_summary(eid)
        assert summary["name"] == "summary-test"
        assert summary["finding_count"] == 2
        assert summary["tool_call_count"] == 2
        assert summary["blocked_count"] == 1


class TestClose:
    def test_close_and_reopen(self, tmp_path):
        db_path = str(tmp_path / "reopen.db")
        store = EngagementStore(db_path=db_path)
        eid = store.create_engagement(name="persist", scope_json="{}", mode="ACTIVE")
        store.close()
        # Reopen and verify data persisted
        store2 = EngagementStore(db_path=db_path)
        eng = store2.get_engagement(eid)
        assert eng["name"] == "persist"
        store2.close()
```

- [ ] Run tests — confirm they fail:

```bash
python3 -m pytest tests/test_engagement_store.py --tb=short 2>&1 | tail -5
# Expected: ERROR — ModuleNotFoundError
```

### Step 7.3 — Implement EngagementStore

- [ ] Create `knowledge/engagement_store.py`:

```python
"""Persistent SQLite audit trail for engagement operations.

Records engagements, findings, tool calls (pass and block), phase transitions,
and approval decisions. Follows the same pattern as TargetStore.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = "/sandbox/knowledge/engagements.db"
_SCHEMA_PATH = Path(__file__).parent / "engagement_schema.sql"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EngagementStore:
    """SQLite-backed persistent store for engagement audit trails."""

    def __init__(self, db_path: str = _DEFAULT_DB_PATH):
        self._db_path = db_path
        self._db: Optional[sqlite3.Connection] = None

    def _get_db(self) -> sqlite3.Connection:
        if self._db is not None:
            return self._db
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self._db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        schema_sql = _SCHEMA_PATH.read_text()
        self._db.executescript(schema_sql)
        return self._db

    # ── Engagements ────────────────────────────────────────────────

    def create_engagement(
        self,
        name: str,
        scope_json: str = "{}",
        mode: str = "PASSIVE",
        max_phase: str = None,
    ) -> int:
        db = self._get_db()
        cur = db.execute(
            "INSERT INTO engagements (name, scope_json, mode, max_phase, started_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, scope_json, mode, max_phase, _now()),
        )
        db.commit()
        return cur.lastrowid

    def end_engagement(self, engagement_id: int, outcome: str = ""):
        db = self._get_db()
        db.execute(
            "UPDATE engagements SET ended_at = ?, outcome = ? WHERE id = ?",
            (_now(), outcome, engagement_id),
        )
        db.commit()

    def get_engagement(self, engagement_id: int) -> Optional[dict]:
        db = self._get_db()
        row = db.execute(
            "SELECT * FROM engagements WHERE id = ?", (engagement_id,),
        ).fetchone()
        return dict(row) if row else None

    # ── Findings ───────────────────────────────────────────────────

    def log_finding(
        self,
        engagement_id: int,
        severity: str,
        category: str,
        title: str,
        detail: str = "",
        target_ip: str = "",
        target_mac: str = "",
    ) -> int:
        db = self._get_db()
        cur = db.execute(
            "INSERT INTO findings (engagement_id, severity, category, title, detail, "
            "target_ip, target_mac, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (engagement_id, severity, category, title, detail,
             target_ip, target_mac, _now()),
        )
        db.commit()
        return cur.lastrowid

    def query_findings(
        self,
        engagement_id: int = 0,
        severity: str = "",
        category: str = "",
    ) -> list[dict]:
        db = self._get_db()
        clauses = []
        params: list[Any] = []
        if engagement_id:
            clauses.append("engagement_id = ?")
            params.append(engagement_id)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if category:
            clauses.append("category = ?")
            params.append(category)
        where = " AND ".join(clauses) if clauses else "1=1"
        rows = db.execute(
            f"SELECT * FROM findings WHERE {where} ORDER BY created_at DESC", params,
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Tool Calls ─────────────────────────────────────────────────

    def log_tool_call(
        self,
        engagement_id: Optional[int] = None,
        tool_name: str = "",
        action: str = "",
        args_json: str = "{}",
        result_summary: str = "",
        success: bool = True,
        blocked: bool = False,
        block_reason: str = "",
        duration_ms: int = 0,
        phase: str = "",
    ) -> int:
        db = self._get_db()
        cur = db.execute(
            "INSERT INTO tool_calls (engagement_id, tool_name, action, args_json, "
            "result_summary, success, blocked, block_reason, duration_ms, phase, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (engagement_id, tool_name, action, args_json, result_summary,
             int(success), int(blocked), block_reason, duration_ms, phase, _now()),
        )
        db.commit()
        return cur.lastrowid

    def query_tool_calls(
        self,
        engagement_id: int = 0,
        tool_name: str = "",
        blocked_only: bool = False,
    ) -> list[dict]:
        db = self._get_db()
        clauses = []
        params: list[Any] = []
        if engagement_id:
            clauses.append("engagement_id = ?")
            params.append(engagement_id)
        if tool_name:
            clauses.append("tool_name = ?")
            params.append(tool_name)
        if blocked_only:
            clauses.append("blocked = 1")
        where = " AND ".join(clauses) if clauses else "1=1"
        rows = db.execute(
            f"SELECT * FROM tool_calls WHERE {where} ORDER BY created_at DESC", params,
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Phase Transitions ──────────────────────────────────────────

    def log_phase_transition(
        self,
        engagement_id: int,
        from_phase: str = "",
        to_phase: str = "",
        reason: str = "",
    ) -> int:
        db = self._get_db()
        cur = db.execute(
            "INSERT INTO phase_transitions (engagement_id, from_phase, to_phase, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (engagement_id, from_phase, to_phase, reason, _now()),
        )
        db.commit()
        return cur.lastrowid

    # ── Summary ────────────────────────────────────────────────────

    def get_engagement_summary(self, engagement_id: int) -> Optional[dict]:
        """Get an engagement summary with finding/tool call counts."""
        eng = self.get_engagement(engagement_id)
        if not eng:
            return None

        db = self._get_db()

        finding_count = db.execute(
            "SELECT COUNT(*) as cnt FROM findings WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchone()["cnt"]

        tool_call_count = db.execute(
            "SELECT COUNT(*) as cnt FROM tool_calls WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchone()["cnt"]

        blocked_count = db.execute(
            "SELECT COUNT(*) as cnt FROM tool_calls WHERE engagement_id = ? AND blocked = 1",
            (engagement_id,),
        ).fetchone()["cnt"]

        return {
            **eng,
            "finding_count": finding_count,
            "tool_call_count": tool_call_count,
            "blocked_count": blocked_count,
        }

    # ── Lifecycle ──────────────────────────────────────────────────

    def close(self):
        if self._db:
            self._db.close()
            self._db = None
```

- [ ] Run tests — confirm all pass:

```bash
python3 -m pytest tests/test_engagement_store.py --tb=short -q
# Expected: ~14 passed
```

### Step 7.4 — Wire EngagementStore into EngagementManager

- [ ] Modify `tools/engagement.py`:

**Add import** at the top:

```python
from knowledge.engagement_store import EngagementStore
```

**Add `engagement_store` attribute** in `__init__` (after `self.scope_config`):

```python
        self.engagement_store: Optional[EngagementStore] = None
```

**Update `start()`** — after the existing body, add audit store logging:

After `logger.info("Engagement '%s' started ...")`, add:

```python
        # Audit trail
        if self.engagement_store:
            try:
                self._store_engagement_id = self.engagement_store.create_engagement(
                    name=name,
                    scope_json=json.dumps(self.scope_config),
                    mode=self._mode.name,
                    max_phase=self.max_phase,
                )
            except Exception as exc:
                logger.warning("Failed to create engagement in store: %s", exc)
                self._store_engagement_id = None
```

Also add `self._store_engagement_id: Optional[int] = None` in `__init__`.

**Update `end()`** — after existing body, before clearing state:

Before `self.active_engagement = None`, add:

```python
        if self.engagement_store and getattr(self, "_store_engagement_id", None):
            try:
                self.engagement_store.end_engagement(self._store_engagement_id, outcome="completed")
            except Exception as exc:
                logger.warning("Failed to end engagement in store: %s", exc)
```

**Update `log_finding()`** — after `self.findings.append(finding)`, add:

```python
        if self.engagement_store and getattr(self, "_store_engagement_id", None):
            try:
                # Extract IPs for structured storage
                ips = self._IP_RE.findall(detail)
                macs = self._MAC_RE.findall(detail)
                self.engagement_store.log_finding(
                    engagement_id=self._store_engagement_id,
                    severity=severity,
                    category=category,
                    title=title,
                    detail=detail,
                    target_ip=ips[0] if ips else "",
                    target_mac=macs[0] if macs else "",
                )
            except Exception as exc:
                logger.warning("Failed to log finding to store: %s", exc)
```

### Step 7.5 — Wire EngagementStore into EnforcementMiddleware

- [ ] Modify `graph/middleware/enforcement.py`:

**Add `engagement_store` parameter** to `__init__`:

```python
    def __init__(
        self,
        engagement_manager,
        scope_validator: Optional[ScopeValidator] = None,
        rate_limiter: Optional[RateLimiter] = None,
        max_phase: Optional[KillChainPhase] = None,
        engagement_store=None,
    ):
        super().__init__()
        self._engagement_manager = engagement_manager
        self._scope_validator = scope_validator
        self._rate_limiter = rate_limiter
        self._max_phase = max_phase
        self._engagement_store = engagement_store
```

**Add audit logging** to `awrap_tool_call` and `wrap_tool_call`. Replace both methods:

```python
    def wrap_tool_call(self, request, handler):
        """Sync enforcement gate."""
        import time
        tool_name = request.tool_call.get("name", "unknown")
        args = request.tool_call.get("args", {})
        action = args.get("action", tool_name)

        blocked = self._enforce(request)
        if blocked:
            self._log_to_store(tool_name, action, args, "", False, True, blocked, 0)
            return blocked

        t0 = time.monotonic()
        result = handler(request)
        duration_ms = int((time.monotonic() - t0) * 1000)

        result_str = ""
        if hasattr(result, "content"):
            result_str = str(result.content)[:200]
        self._log_to_store(tool_name, action, args, result_str, True, False, "", duration_ms)
        return result

    async def awrap_tool_call(self, request, handler):
        """Async enforcement gate."""
        import time
        tool_name = request.tool_call.get("name", "unknown")
        args = request.tool_call.get("args", {})
        action = args.get("action", tool_name)

        blocked = self._enforce(request)
        if blocked:
            self._log_to_store(tool_name, action, args, "", False, True, blocked, 0)
            return blocked

        t0 = time.monotonic()
        result = await handler(request)
        duration_ms = int((time.monotonic() - t0) * 1000)

        result_str = ""
        if hasattr(result, "content"):
            result_str = str(result.content)[:200]
        self._log_to_store(tool_name, action, args, result_str, True, False, "", duration_ms)
        return result

    def _log_to_store(
        self, tool_name: str, action: str, args: dict,
        result_summary: str, success: bool,
        blocked: bool, block_reason: str, duration_ms: int,
    ):
        """Best-effort logging to EngagementStore."""
        if not self._engagement_store:
            return
        if not self._is_pentest_tool(tool_name):
            return
        try:
            import json
            mgr = self._engagement_manager
            engagement_id = getattr(mgr, "_store_engagement_id", None)
            phase = ""
            tool_phase = get_tool_phase(action)
            if tool_phase:
                phase = tool_phase.name
            self._engagement_store.log_tool_call(
                engagement_id=engagement_id,
                tool_name=tool_name,
                action=action,
                args_json=json.dumps(args, default=str),
                result_summary=result_summary,
                success=success,
                blocked=blocked,
                block_reason=block_reason,
                duration_ms=duration_ms,
                phase=phase,
            )
        except Exception as exc:
            logger.warning("Failed to log tool call to engagement store: %s", exc)
```

### Step 7.6 — Wire EngagementStore in lg_tools.py and graph/agent.py

- [ ] In `tools/lg_tools.py` `_init_pentest_singletons()`, after `_engagement.target_store = _target_store`, add:

```python
    from knowledge.engagement_store import EngagementStore
    _engagement.engagement_store = EngagementStore()
```

- [ ] In `graph/agent.py` `_build_middleware()`, update the `EnforcementMiddleware` construction to pass the store:

```python
        middleware.append(EnforcementMiddleware(
            engagement_manager=engagement_manager,
            scope_validator=scope_validator,
            rate_limiter=rate_limiter,
            max_phase=max_phase,
            engagement_store=getattr(engagement_manager, 'engagement_store', None),
        ))
```

### Step 7.7 — Verify

- [ ] Run engagement store tests:

```bash
python3 -m pytest tests/test_engagement_store.py --tb=short -q
# Expected: ~14 passed
```

- [ ] Run full suite to check for regressions:

```bash
python3 -m pytest tests/ --tb=short -q
# Expected: 244 original + all new tests = green
```

- [ ] Commit:

```bash
git add knowledge/engagement_schema.sql knowledge/engagement_store.py \
       tests/test_engagement_store.py tools/engagement.py \
       graph/middleware/enforcement.py graph/agent.py tools/lg_tools.py
git commit -m "feat: SQLite EngagementStore audit trail wired into middleware and manager"
```

---

## Final Verification

- [ ] Run the complete test suite one final time:

```bash
python3 -m pytest tests/ --tb=short -v
```

Expected output: 244 original tests + ~90 new tests = all green, 0 failures.

- [ ] Verify new file structure:

```
enforcement/
  __init__.py
  scope.py
  phases.py
  rate_limiter.py
knowledge/
  engagement_schema.sql
  engagement_store.py
graph/middleware/
  enforcement.py
tests/
  test_scope_validator.py
  test_kill_chain.py
  test_rate_limiter.py
  test_enforcement_middleware.py
  test_engagement_store.py
```

- [ ] Verify modified files:

```
graph/agent.py           — EnforcementMiddleware wired first in chain
tools/lg_tools.py        — get_engagement_manager() accessor + engagement_store wiring
tools/engagement.py      — max_phase, scope_config, engagement_store attrs
tools/blackarch.py       — shell_exec deny-by-default lockdown
config/engagement-config.json — scope, max_phase, rate_limits added
server.py                — passes engagement_manager to graph builder
```

---

## Summary of Enforcement Flow

```
User message → LangGraph agent → tool call decision
                                        │
                                        ▼
                            EnforcementMiddleware._enforce()
                                        │
                            ┌───────────┴───────────┐
                            │  Not pentest tool?     │──→ PASS THROUGH
                            ├────────────────────────┤
                            │  Engagement tool?      │──→ EXEMPT (pass)
                            ├────────────────────────┤
                            │  No active engagement? │──→ BLOCKED
                            ├────────────────────────┤
                            │  Mode check fails?     │──→ BLOCKED
                            ├────────────────────────┤
                            │  Target out of scope?  │──→ BLOCKED
                            ├────────────────────────┤
                            │  Phase > ceiling?       │──→ BLOCKED
                            ├────────────────────────┤
                            │  Rate limit exceeded?  │──→ BLOCKED
                            └────────────┬───────────┘
                                        │
                                        ▼
                                   handler(request)  ──→ tool executes
                                        │
                                        ▼
                                AuditMiddleware logs
                                        │
                                        ▼
                              EngagementStore records
```
