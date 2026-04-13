"""EnforcementMiddleware — hard enforcement gate for pentest tool calls.

Checks (in order):
  1. Is this a pentest tool? If not, pass through.
  2. Is this the engagement tool itself? If so, exempt.
  3. Is there an active engagement? Block if not.
  4. Is the tool permitted under the current engagement mode? Block if not.
  5. Is the target within scope? Block if not.
  6. Is the tool within the kill chain phase ceiling? Block if not.
  7. Is the tool within rate limits? Block if not.

Must be placed FIRST in the middleware chain (before AuditMiddleware)
so that blocked calls are still logged by audit but never executed.
"""
from __future__ import annotations

import logging
from typing import Optional

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage

from enforcement.phases import KillChainPhase, get_tool_phase
from enforcement.rate_limiter import RateLimiter
from enforcement.scope import ScopeValidator

logger = logging.getLogger(__name__)

# Pentest tool prefixes — mirrored from guardrails._PENTEST_TOOL_PREFIXES
# to avoid importing guardrails.py (which uses Python 3.10+ syntax locally).
_PENTEST_TOOL_PREFIXES = {
    "portapack", "flipper", "marauder", "blackarch", "engagement",
    "device_manager",
    # Phase 2 — Recon
    "dns_enum", "subdomain_discovery", "osint_recon",
    # Phase 2 — Enumeration
    "web_enum", "service_enum", "ssl_audit", "api_enum",
    # Phase 2 — Vuln Assessment
    "vuln_scan", "sql_test", "web_vuln", "cve_match",
    # Phase 2 — Exploitation
    "msf_exploit", "credential_attack", "hashcat_rules",
    # Phase 2 — Post-Exploitation + Lateral Movement
    "priv_esc", "lateral_move", "data_exfil", "persistence", "cleanup",
}

# The engagement tool itself must be exempt — otherwise you can't
# start or query an engagement.
_EXEMPT_TOOLS = {"engagement", "device_manager"}


class EnforcementMiddleware(AgentMiddleware):
    """Hard enforcement gate for pentest tool calls.

    Args:
        engagement_manager: An EngagementManager instance.
        scope_validator: Optional ScopeValidator for target scope checks.
        rate_limiter: Optional RateLimiter for call frequency limits.
        max_phase: Optional KillChainPhase ceiling.
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

    def _blocked_response(self, request, message: str) -> ToolMessage:
        """Return a ToolMessage so the tool_use/tool_result pairing stays valid."""
        tool_call_id = request.tool_call.get("id", "")
        return ToolMessage(content=message, tool_call_id=tool_call_id)

    def wrap_tool_call(self, request, handler):
        """Sync enforcement gate."""
        blocked = self._enforce(request)
        if blocked:
            return self._blocked_response(request, blocked)
        return handler(request)

    async def awrap_tool_call(self, request, handler):
        """Async enforcement gate."""
        blocked = self._enforce(request)
        if blocked:
            return self._blocked_response(request, blocked)
        return await handler(request)

    def _enforce(self, request) -> Optional[str]:
        """Run all enforcement checks.

        Returns None if all checks pass.
        Returns a BLOCKED error string if any check fails.
        """
        tool_name = request.tool_call.get("name", "unknown")
        args = request.tool_call.get("args", {})

        # ── Check 1: Is this a pentest tool? ──
        if not self._is_pentest_tool(tool_name):
            return None

        # ── Check 2: Is this an exempt tool? ──
        if tool_name in _EXEMPT_TOOLS:
            return None

        # For tool actions dispatched through a parent tool (e.g. blackarch.nmap_scan),
        # check the action name from args.
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
                "BLOCKED %s: mode %s insufficient (risk=%s)",
                action, mgr.mode.name, risk,
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

        return None

    @staticmethod
    def _is_pentest_tool(tool_name: str) -> bool:
        """Check if a tool name belongs to the pentest domain.

        Matches by: (a) exact name in prefix set, (b) first word prefix in
        prefix set, or (c) tool_name is a known action in the phase map
        (handles cases where the action name is used directly as tool_name).
        """
        if tool_name in _PENTEST_TOOL_PREFIXES:
            return True
        prefix = tool_name.split("_")[0] if "_" in tool_name else tool_name
        if prefix in _PENTEST_TOOL_PREFIXES:
            return True
        # Also match known pentest actions (e.g. nmap_scan, wifi_deauth)
        return get_tool_phase(tool_name) is not None
