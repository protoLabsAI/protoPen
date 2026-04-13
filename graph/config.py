"""LangGraph configuration loader for protoPen."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class SubagentDef:
    enabled: bool = True
    tools: list[str] = field(default_factory=list)
    max_turns: int = 30


@dataclass
class LangGraphConfig:
    # Model settings
    model_provider: str = "openai"  # openai (gateway) or vllm
    model_name: str = "claude-sonnet-4-6"
    api_base: str = "http://gateway:4000/v1"
    api_key: str = ""  # set via OPENAI_API_KEY env (gateway master key)
    temperature: float = 0.3
    max_tokens: int = 4096
    max_iterations: int = 75

    # Subagents
    threat_scanner: SubagentDef = field(default_factory=lambda: SubagentDef(
        tools=["cve_search", "security_feeds", "github_trending", "browser", "security_memory"],
        max_turns=30,
    ))
    vuln_analyst: SubagentDef = field(default_factory=lambda: SubagentDef(
        tools=["cve_search", "browser", "security_memory", "target_intel"],
        max_turns=40,
    ))
    intel_reporter: SubagentDef = field(default_factory=lambda: SubagentDef(
        tools=["security_memory", "discord_feed"],
        max_turns=20,
    ))

    # Middleware toggles
    knowledge_middleware: bool = True
    audit_middleware: bool = True
    memory_middleware: bool = True
    enforcement_middleware: bool = True

    # Enforcement
    enforcement_max_phase: str = ""  # kill-chain ceiling (e.g. "enumeration"), empty = no ceiling

    # Knowledge store
    knowledge_db_path: str = "/sandbox/knowledge/research.db"
    embed_model: str = "qwen3-embedding:0.6b"
    knowledge_top_k: int = 10
    knowledge_search_mode: str = "hybrid"  # hybrid, vector, keyword
    knowledge_enrich_chunks: bool = True  # contextual enrichment at index time

    @classmethod
    def from_yaml(cls, path: str | Path) -> "LangGraphConfig":
        """Load config from YAML file."""
        p = Path(path)
        if not p.exists():
            return cls()

        with open(p) as f:
            data = yaml.safe_load(f) or {}

        model = data.get("model", {})
        subagents = data.get("subagents", {})
        middleware = data.get("middleware", {})
        knowledge = data.get("knowledge", {})

        config = cls(
            model_provider=model.get("provider", cls.model_provider),
            model_name=model.get("name", cls.model_name),
            api_base=model.get("api_base", cls.api_base),
            api_key=model.get("api_key", cls.api_key),
            temperature=model.get("temperature", cls.temperature),
            max_tokens=model.get("max_tokens", cls.max_tokens),
            max_iterations=model.get("max_iterations", cls.max_iterations),
            knowledge_middleware=middleware.get("knowledge", True),
            audit_middleware=middleware.get("audit", True),
            memory_middleware=middleware.get("memory", True),
            knowledge_db_path=knowledge.get("db_path", cls.knowledge_db_path),
            embed_model=knowledge.get("embed_model", cls.embed_model),
            knowledge_top_k=knowledge.get("top_k", cls.knowledge_top_k),
            knowledge_search_mode=knowledge.get("search_mode", cls.knowledge_search_mode),
            knowledge_enrich_chunks=knowledge.get("enrich_chunks", cls.knowledge_enrich_chunks),
        )

        for name in ("threat_scanner", "vuln_analyst", "intel_reporter"):
            if name in subagents:
                sub = subagents[name]
                setattr(config, name, SubagentDef(
                    enabled=sub.get("enabled", True),
                    tools=sub.get("tools", getattr(config, name).tools),
                    max_turns=sub.get("max_turns", getattr(config, name).max_turns),
                ))

        return config
