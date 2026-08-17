"""Native-OAuth subagents (ADR 0097, port of protoAgent #2552).

A Claude/ChatGPT-subscription instance could CHAT while every delegation failed:
the subagent stack builds its own middleware list and carried neither native-OAuth
wire-shape transform, so it emitted a system-role input item (which the Codex
Responses backend rejects outright) or traffic with no Claude Code identity line
(which Anthropic's OAuth infra refuses). The lead stack (`_build_middleware`) and the
subagent stack (`_subagent_middleware`) now share `provider_shape_middleware`; these
pin that they stay in step so a future transform can't be added to one and missed by
the other.
"""

from __future__ import annotations

from graph.agent import _subagent_middleware, provider_shape_middleware
from graph.config import LangGraphConfig


def _names(mws) -> list[str]:
    return [type(m).__name__ for m in mws]


# ── the shared helper ─────────────────────────────────────────────────────────


def test_provider_shape_helper_per_provider():
    def names(provider):
        return _names(provider_shape_middleware(LangGraphConfig(model_provider=provider)))

    assert names("anthropic-oauth") == ["ClaudeCodeIdentityMiddleware"]
    assert names("openai-codex") == ["CodexResponsesInputMiddleware"]
    assert names("openai") == []  # gateway: nothing to reshape
    assert names("vllm") == []


def test_provider_shape_helper_is_case_and_whitespace_tolerant():
    cfg = LangGraphConfig(model_provider="  Anthropic-OAuth  ")
    assert _names(provider_shape_middleware(cfg)) == ["ClaudeCodeIdentityMiddleware"]


# ── the subagent stack actually mounts them ───────────────────────────────────


def _sub(provider: str, *, enforcement=False, audit=False):
    # enforcement/audit off by default so the test isolates the PROVIDER-shape
    # addition (enforcement would need a live engagement manager).
    cfg = LangGraphConfig(
        model_provider=provider,
        enforcement_middleware=enforcement,
        audit_middleware=audit,
    )
    return _names(_subagent_middleware(cfg))


def test_subagent_stack_mounts_provider_shape():
    assert _sub("anthropic-oauth") == ["ClaudeCodeIdentityMiddleware"]
    assert _sub("openai-codex") == ["CodexResponsesInputMiddleware"]
    # Gateway delegations carry no provider-shape transform.
    assert _sub("openai") == []


def test_subagent_provider_shape_is_appended_last():
    # The transform must see the FINAL system message, so it sits innermost (last)
    # in the subagent list — after the audit rail, not before it.
    names = _sub("anthropic-oauth", audit=True)
    assert names[-1] == "ClaudeCodeIdentityMiddleware"
    assert "AuditMiddleware" in names
