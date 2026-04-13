"""KnowledgeIngestMiddleware — auto-stores tool findings into the knowledge store.

Uses a small/fast LLM (e.g. claude-haiku) to extract structured findings
from tool output, then stores them as threat intel. This avoids brittle
hardcoded parsing and handles any tool output format gracefully.

Falls back to the deterministic parser registry when no LLM is available.
"""
from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage

if TYPE_CHECKING:
    from knowledge.store import KnowledgeStore

logger = logging.getLogger(__name__)

_EXTRACT_PROMPT = """\
Extract security findings from this tool output as a JSON array.
Each finding: {{"type": "...", "severity": "critical|high|medium|low|info", "summary": "...", "details": "..."}}.
If no actionable findings, return [].
Return ONLY valid JSON, no explanation.

Tool: {tool_name}/{action}
Output:
{content}"""

# Tools worth ingesting findings from.
_INGESTIBLE_TOOLS: set[str] = {
    # Blue-team
    "cis_audit", "net_monitor", "hardening_check", "ir_toolkit", "purple_team",
    # Red-team (high-signal)
    "vuln_scan", "web_vuln", "sql_test", "ssl_audit", "cve_match",
    "credential_attack", "priv_esc",
}


class KnowledgeIngestMiddleware(AgentMiddleware):
    """Auto-ingest tool findings into the knowledge store after execution.

    Primary path: small LLM extracts structured findings from raw output.
    Fallback path: deterministic parser registry (tools/parsers/).
    """

    def __init__(
        self,
        knowledge_store: "KnowledgeStore",
        model_name: str = "",
        api_base: str = "",
    ):
        super().__init__()
        self._store = knowledge_store
        self._model_name = model_name or os.environ.get(
            "INGEST_MODEL", "claude-haiku-4-5",
        )
        self._api_base = api_base or os.environ.get(
            "INGEST_API_BASE", "http://gateway:4000/v1",
        )
        self._llm = None
        self._llm_available: bool | None = None  # tri-state: None = untested

    def _get_llm(self):
        if self._llm is None:
            from langchain_openai import ChatOpenAI
            self._llm = ChatOpenAI(
                base_url=self._api_base,
                api_key=os.environ.get("OPENAI_API_KEY", ""),
                model=self._model_name,
                temperature=0,
                max_tokens=1024,
            )
        return self._llm

    def wrap_tool_call(self, request, handler):
        result = handler(request)
        self._try_ingest(request, result)
        return result

    async def awrap_tool_call(self, request, handler):
        result = await handler(request)
        self._try_ingest(request, result)
        return result

    def _try_ingest(self, request, result) -> None:
        """Extract and store findings from tool output (fire-and-forget)."""
        tool_name = request.tool_call.get("name", "")
        args = request.tool_call.get("args", {})
        action = args.get("action", "")

        if tool_name not in _INGESTIBLE_TOOLS:
            return

        content = ""
        if isinstance(result, ToolMessage):
            content = result.content if isinstance(result.content, str) else str(result.content)
        elif isinstance(result, str):
            content = result

        if not content or content.startswith("[BLOCKED]") or content.startswith("Error"):
            return

        # Truncate large outputs to stay within small-model context
        if len(content) > 4000:
            content = content[:4000] + "\n... [truncated]"

        # Try LLM extraction first, fall back to deterministic parsers
        findings = self._extract_via_llm(tool_name, action, content)
        if findings is None:
            findings = self._extract_via_parsers(tool_name, action, content)

        if not findings:
            return

        source_type = "defensive_scan" if tool_name in {
            "cis_audit", "net_monitor", "hardening_check", "ir_toolkit", "purple_team",
        } else "vulnerability_scan"
        ingested = 0

        for finding in findings:
            try:
                self._store.add_threat_intel(
                    content=json.dumps(finding, default=str),
                    source=f"{tool_name}/{action}",
                    source_type=source_type,
                    topic=finding.get("type", "finding"),
                    intel_type="finding",
                    severity=finding.get("severity", ""),
                )
                ingested += 1
            except Exception:
                logger.debug("Failed to store finding from %s/%s", tool_name, action, exc_info=True)

        if ingested:
            logger.info("Auto-ingested %d findings from %s/%s", ingested, tool_name, action)

    # ── LLM extraction ───────────────────────────────────────────────────

    def _extract_via_llm(self, tool_name: str, action: str, content: str) -> list[dict] | None:
        """Use a small model to extract structured findings. Returns None on failure."""
        # If we've already confirmed LLM is unavailable, skip
        if self._llm_available is False:
            return None

        try:
            llm = self._get_llm()
            prompt = _EXTRACT_PROMPT.format(
                tool_name=tool_name, action=action, content=content,
            )
            response = llm.invoke(prompt)
            self._llm_available = True

            raw_text = response.content if isinstance(response.content, str) else str(response.content)
            raw_text = raw_text.strip()

            # Strip markdown code fences if present
            if raw_text.startswith("```"):
                raw_text = raw_text.split("\n", 1)[-1]
                if raw_text.endswith("```"):
                    raw_text = raw_text[:-3].strip()

            parsed = json.loads(raw_text)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
            return []
        except Exception:
            if self._llm_available is None:
                # First failure — mark LLM as unavailable so we don't keep retrying
                logger.info("Ingest LLM unavailable, falling back to deterministic parsers")
                self._llm_available = False
            else:
                logger.debug("LLM extraction failed for %s/%s", tool_name, action, exc_info=True)
            return None

    # ── Deterministic parser fallback ────────────────────────────────────

    @staticmethod
    def _extract_via_parsers(tool_name: str, action: str, content: str) -> list[dict]:
        """Fallback: use the deterministic parser registry."""
        from tools.parsers import PARSER_MAP

        parser_key = (tool_name, action)
        if parser_key not in PARSER_MAP:
            return []

        try:
            return PARSER_MAP[parser_key](content, _NullStore())
        except Exception:
            logger.debug("Parser fallback failed for %s/%s", tool_name, action, exc_info=True)
            return []


class _NullStore:
    """No-op stand-in for TargetStore.

    Some parsers (e.g. net_monitor.host_discovery) call store.upsert_host().
    When ingesting into the knowledge store we don't want those side effects.
    """

    def __getattr__(self, name):
        return lambda *a, **kw: None
