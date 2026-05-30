"""Context compaction wiring — default-on SummarizationMiddleware + resilient trigger."""

from __future__ import annotations

from graph.agent import _build_middleware, _parse_compaction_trigger
from graph.config import LangGraphConfig


def _has_summarizer(middleware) -> bool:
    return any(m.__class__.__name__ == "SummarizationMiddleware" for m in middleware)


def test_parse_trigger():
    assert _parse_compaction_trigger("fraction:0.8") == ("fraction", 0.8)
    assert _parse_compaction_trigger("tokens:120000") == ("tokens", 120000)
    assert _parse_compaction_trigger("messages:80") == ("messages", 80)
    assert _parse_compaction_trigger("garbage") == ("fraction", 0.8)  # safe fallback


def test_compaction_on_by_default(monkeypatch):
    """Compaction is a default-on safety net against context overflow."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    cfg = LangGraphConfig()
    assert cfg.compaction_enabled
    assert _has_summarizer(_build_middleware(cfg, knowledge_store=None))


def test_compaction_can_be_disabled(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    cfg = LangGraphConfig(compaction_enabled=False)
    assert not _has_summarizer(_build_middleware(cfg, knowledge_store=None))


def test_compaction_fraction_trigger_falls_back_without_model_profile(monkeypatch):
    """A `fraction:` trigger needs the model's context-window profile, which a
    custom gateway alias (protolabs/reasoning) lacks — langchain raises at
    construction. The wiring must degrade to a message-count trigger, not crash
    the whole graph at load."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    cfg = LangGraphConfig(compaction_trigger="fraction:0.8")
    assert cfg.compaction_trigger.startswith("fraction:")
    # Must not raise even though the alias has no context-window profile.
    assert _has_summarizer(_build_middleware(cfg, knowledge_store=None))
