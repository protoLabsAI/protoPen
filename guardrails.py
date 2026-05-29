"""Guardrails for protoPen.

- Scope validation before tool calls (0-100 score, threshold 60)
- Query rewriting on sparse results
- SHA256 response caching with TTL
- Binary document relevance grading
- Engagement mode enforcement (pentest tool gating)
"""

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

import httpx

# Gateway endpoint + key for guardrail/utility LLM calls. Sourced from the same
# env the main agent uses (OPENAI_BASE_URL = the protoLabs gateway,
# OPENAI_API_KEY = GATEWAY_API_KEY), so guardrails work wherever protopen runs —
# including the Tailscale-native Deck — instead of assuming a Docker-internal
# gateway with a placeholder token.
_GW_BASE = os.environ.get("OPENAI_BASE_URL", "https://api.proto-labs.ai").rstrip("/")
_GATEWAY_URL = _GW_BASE if _GW_BASE.endswith("/v1") else _GW_BASE + "/v1"
_GATEWAY_KEY = os.environ.get("OPENAI_API_KEY", "")

# ---------------------------------------------------------------------------
# Guardrails — validate query is within security research scope
# ---------------------------------------------------------------------------

_GUARDRAIL_PROMPT = """Score this query's relevance to cybersecurity research on a scale of 0-100.

Categories that score HIGH (70-100):
- CVE analysis, vulnerability research, exploit tracking
- Penetration testing, red teaming, offensive security
- Network security, wireless attacks, RF security
- IoT/embedded security, firmware analysis
- Security tools (nmap, nuclei, metasploit, hashcat, etc.)
- Threat intelligence, OSINT, reconnaissance
- Security advisories, CERT alerts, vendor patches
- Questions about the agent's own capabilities, cron jobs, settings, status
- Meta-questions about security workflow, tools, topics being tracked
- Infrastructure security, DevSecOps, hardening

Categories that score LOW (0-30):
- Cooking, sports, entertainment, politics
- Celebrity gossip, relationship advice
- Completely unrelated topics with zero tech connection

Respond with ONLY a JSON object like this example: {{"score": 25, "reason": "brief reason"}}

Query: {query}"""


async def check_guardrail(query: str, llm_url: str = _GATEWAY_URL, threshold: int = 40) -> dict:
    """Check if a query is within security research scope.

    Returns: {"pass": bool, "score": int, "reason": str}
    """
    if not query.strip():
        return {"pass": True, "score": 100, "reason": "empty query"}

    # Quick heuristic bypass for obvious security queries
    security_keywords = [
        "cve",
        "exploit",
        "vulnerability",
        "advisory",
        "threat",
        "intel",
        "pentest",
        "recon",
        "scan",
        "nmap",
        "nuclei",
        "burp",
        "metasploit",
        "wifi",
        "bluetooth",
        "rfid",
        "flipper",
        "portapack",
        "marauder",
        "github",
        "discord",
        "digest",
        "osint",
        "shodan",
        "censys",
        "target",
        "engagement",
        "finding",
        "severity",
        "cvss",
        "cron",
        "schedule",
        "job",
        "topic",
        "status",
        "tool",
        "help",
        "setting",
        "config",
        "what do you",
        "what can you",
        "your",
        "publish",
        "report",
        "weekly",
        "lab",
        "experiment",
    ]
    query_lower = query.lower()
    if any(kw in query_lower for kw in security_keywords):
        return {"pass": True, "score": 90, "reason": "keyword match"}

    # LLM-based check
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{llm_url}/chat/completions",
                headers={"Authorization": f"Bearer {_GATEWAY_KEY}"},
                json={
                    "model": "protolabs/nano",
                    "messages": [{"role": "user", "content": _GUARDRAIL_PROMPT.format(query=query)}],
                    "max_tokens": 100,
                    "temperature": 0.1,
                },
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            # Parse JSON from response — handle think blocks, markdown fences
            import re

            content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
            content = re.sub(r"```json?\s*", "", content).replace("```", "").strip()
            result = json.loads(content)
            score = int(result["score"])
            reason = result.get("reason", "")
            return {"pass": score >= threshold, "score": score, "reason": reason}
    except Exception as e:
        # Fallback: allow the query (don't block on guardrail failure)
        print(f"[guardrail] Check failed: {e}", flush=True)
        return {"pass": True, "score": 50, "reason": f"guardrail check failed ({e}), allowing"}


# ---------------------------------------------------------------------------
# Response caching — SHA256(query) with TTL
# ---------------------------------------------------------------------------

_CACHE_DB_PATH = Path("/sandbox/knowledge/cache.db")
_CACHE_TTL = 86400  # 24 hours


def _get_cache_db() -> sqlite3.Connection:
    _CACHE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(_CACHE_DB_PATH), check_same_thread=False)
    db.execute("""
        CREATE TABLE IF NOT EXISTS response_cache (
            key TEXT PRIMARY KEY,
            response TEXT NOT NULL,
            created_at REAL NOT NULL
        )
    """)
    db.commit()
    return db


_cache_db = None


def _cache_key(query: str) -> str:
    normalized = query.strip().lower()
    return hashlib.sha256(normalized.encode()).hexdigest()


def cache_get(query: str) -> str | None:
    """Check cache for a previous response. Returns None on miss."""
    global _cache_db
    if _cache_db is None:
        try:
            _cache_db = _get_cache_db()
        except Exception:
            return None

    key = _cache_key(query)
    try:
        row = _cache_db.execute("SELECT response, created_at FROM response_cache WHERE key = ?", (key,)).fetchone()
        if row:
            response, created_at = row
            if time.time() - created_at < _CACHE_TTL:
                return response
            # Expired — delete
            _cache_db.execute("DELETE FROM response_cache WHERE key = ?", (key,))
            _cache_db.commit()
    except Exception:
        pass
    return None


def cache_set(query: str, response: str):
    """Store a response in cache."""
    global _cache_db
    if _cache_db is None:
        try:
            _cache_db = _get_cache_db()
        except Exception:
            return

    key = _cache_key(query)
    try:
        _cache_db.execute(
            "INSERT OR REPLACE INTO response_cache (key, response, created_at) VALUES (?, ?, ?)",
            (key, response, time.time()),
        )
        _cache_db.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Document grading — quick binary relevance check
# ---------------------------------------------------------------------------

_GRADE_PROMPT = """Is this document relevant to the security query? Answer with ONLY "yes" or "no".

Security query: {query}

Document excerpt (first 500 chars):
{excerpt}"""


async def grade_document(query: str, content: str, llm_url: str = _GATEWAY_URL) -> bool:
    """Quick binary relevance check. Returns True if relevant."""
    if not content or len(content.strip()) < 50:
        return False  # Too short to be useful

    excerpt = content[:500]

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{llm_url}/chat/completions",
                headers={"Authorization": f"Bearer {_GATEWAY_KEY}"},
                json={
                    "model": "protolabs/nano",
                    "messages": [{"role": "user", "content": _GRADE_PROMPT.format(query=query, excerpt=excerpt)}],
                    "max_tokens": 10,
                    "temperature": 0.1,
                },
            )
            resp.raise_for_status()
            answer = resp.json()["choices"][0]["message"]["content"].strip().lower()
            return answer.startswith("yes")
    except Exception:
        # Fallback heuristic: content length > 50 chars = relevant
        return len(content.strip()) > 50


# ---------------------------------------------------------------------------
# Query rewriting — improve sparse queries
# ---------------------------------------------------------------------------

_REWRITE_PROMPT = """The following security query returned sparse or no results. Rewrite it to be more effective for searching CVEs, exploits, advisories, and security tools.

Original query: {query}

Respond with ONLY the rewritten query (no explanation)."""


async def rewrite_query(query: str, llm_url: str = _GATEWAY_URL) -> str:
    """Rewrite a query for better search results."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{llm_url}/chat/completions",
                headers={"Authorization": f"Bearer {_GATEWAY_KEY}"},
                json={
                    "model": "protolabs/nano",
                    "messages": [{"role": "user", "content": _REWRITE_PROMPT.format(query=query)}],
                    "max_tokens": 200,
                    "temperature": 0.3,
                },
            )
            resp.raise_for_status()
            rewritten = resp.json()["choices"][0]["message"]["content"].strip()
            return rewritten if rewritten else query
    except Exception:
        # Fallback: simple keyword expansion
        expansions = {
            "moe": "mixture of experts MoE",
            "rag": "retrieval augmented generation RAG",
            "rlhf": "reinforcement learning human feedback RLHF",
            "dpo": "direct preference optimization DPO",
            "lora": "low-rank adaptation LoRA fine-tuning",
        }
        result = query
        for short, expanded in expansions.items():
            if short in query.lower():
                result = result + " " + expanded
                break
        return result


# ---------------------------------------------------------------------------
# Engagement mode enforcement — pentest tool gating
# ---------------------------------------------------------------------------

# Tools that require engagement mode checks (maps tool action → risk key
# in engagement-config.json tool_risk table).
_PENTEST_TOOL_PREFIXES = {
    "portapack",
    "flipper",
    "marauder",
    "blackarch",
    "engagement",
    "device_manager",
    "traffic",  # traffic_analysis — tls_intercept is REDTEAM-level
}


def check_engagement_mode(tool_name: str, engagement_manager: Any) -> dict:
    """Pre-flight check: is the requested tool permitted under the current engagement mode?

    Args:
        tool_name: The tool action key (e.g. "wifi_deauth", "flip_subghz_tx").
        engagement_manager: An EngagementManager instance (from tools.engagement).

    Returns:
        {"pass": bool, "mode": str, "reason": str}
    """
    if engagement_manager is None:
        return {"pass": True, "mode": "unknown", "reason": "no engagement manager — skipping check"}

    # Only gate pentest tools; security research tools pass through unconditionally
    tool_prefix = tool_name.split("_")[0] if "_" in tool_name else tool_name
    if tool_prefix not in _PENTEST_TOOL_PREFIXES and tool_name not in _PENTEST_TOOL_PREFIXES:
        return {"pass": True, "mode": engagement_manager.mode.name, "reason": "non-pentest tool"}

    allowed = engagement_manager.is_allowed(tool_name)
    mode = engagement_manager.mode
    if allowed:
        return {
            "pass": True,
            "mode": mode.name,
            "reason": f"tool '{tool_name}' permitted at {mode.name} level",
        }

    risk = engagement_manager._tool_risk.get(tool_name, 0)
    required_modes = {0: "PASSIVE", 1: "ACTIVE", 2: "REDTEAM"}
    required = required_modes.get(risk, f"risk={risk}")
    return {
        "pass": False,
        "mode": mode.name,
        "reason": (
            f"tool '{tool_name}' requires {required} mode "
            f"(risk={risk}), current mode is {mode.name} (level={mode.value})"
        ),
    }
