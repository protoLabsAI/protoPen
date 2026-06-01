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
    threat_scanner: SubagentDef = field(
        default_factory=lambda: SubagentDef(
            tools=["cve_search", "security_feeds", "github_trending", "browser", "security_memory"],
            max_turns=30,
        )
    )
    vuln_analyst: SubagentDef = field(
        default_factory=lambda: SubagentDef(
            tools=["cve_search", "browser", "security_memory", "target_intel"],
            max_turns=40,
        )
    )
    intel_reporter: SubagentDef = field(
        default_factory=lambda: SubagentDef(
            tools=["security_memory", "discord_feed"],
            max_turns=20,
        )
    )

    # Auxiliary model — a single cheap/fast alias for the non-reasoning calls
    # (context summarization, subagent delegation). Each path uses its own
    # specific override if set (e.g. compaction.model, a per-subagent model),
    # else falls back to this, else the main model. Blank = main model
    # everywhere. Set via routing.aux_model in the YAML.
    aux_model: str = ""

    # Middleware toggles
    knowledge_middleware: bool = True
    knowledge_ingest_middleware: bool = True
    audit_middleware: bool = True
    memory_middleware: bool = True
    enforcement_middleware: bool = True

    # Checkpoint pruning — keeps the SQLite session DB from growing unbounded.
    # Keep the latest N checkpoints per chat session, and TTL whole sessions idle
    # past max_age_days. Runs every prune_interval_hours (0 disables the sweep).
    checkpoint_keep_per_thread: int = 5
    checkpoint_max_age_days: int = 30
    checkpoint_prune_interval_hours: int = 6

    # Per-tool execution backstop — caps any single tool call so a hung tool
    # (broken/missing internal timeout, dead peer) can't wedge the whole turn.
    # Generous by design (a backstop, not a tight bound); `task` subagent
    # delegation is exempt. <= 0 disables. See graph/middleware/timeout.py.
    tool_timeout_middleware: bool = True
    tool_timeout_seconds: int = 600

    # Enforcement
    enforcement_max_phase: str = ""  # kill-chain ceiling (e.g. "enumeration"), empty = no ceiling

    # Context compaction — wires langchain's SummarizationMiddleware to summarize
    # old history near the context limit. ON by default (a long autonomous
    # session would otherwise overflow the window). trigger is
    # "fraction:0.8" | "tokens:120000" | "messages:80"; keep = last N messages.
    # NOTE: "fraction:"/"tokens:" triggers need the model's context-window
    # profile; for a custom gateway alias that lacks one, the wiring falls back
    # to a message-count trigger (see graph/agent.py) instead of crashing.
    compaction_enabled: bool = True
    compaction_trigger: str = "fraction:0.8"
    compaction_keep_messages: int = 20
    compaction_model: str = ""  # blank = summarize with the main model

    # Knowledge store
    knowledge_db_path: str = "/sandbox/knowledge/research.db"
    embed_model: str = "qwen3-embedding:0.6b"
    knowledge_top_k: int = 10
    knowledge_search_mode: str = "hybrid"  # hybrid, vector, keyword
    knowledge_enrich_chunks: bool = True  # contextual enrichment at index time

    # Workflows — declarative multi-step subagent recipes (ADR 0002), exposed via
    # the run_workflow tool. Bundled examples ship in the repo workflows/ dir;
    # workflow_dir is the writable root for user/agent-emitted recipes (same
    # /sandbox→~/.protopen fallback, resolved in server.py).
    workflows_enabled: bool = True
    workflow_dir: str = "/sandbox/workflows"

    # Skills — human-authored SKILL.md folders (AgentSkills format) loaded into an
    # FTS5 index and retrieved at inference by KnowledgeMiddleware (injected as a
    # <learned_skills> block). Bundled examples ship in config/skills/; `dir` is
    # the writable root for user drop-ins (/sandbox→~/.protopen fallback).
    skills_enabled: bool = True
    skills_dir: str = "/sandbox/skills"
    skills_db_path: str = "/sandbox/skills.db"
    skills_top_k: int = 5

    # Deferred tools (ADR 0005 #3 — progressive tool disclosure). OFF by default.
    # When on, most tool *schemas* are withheld from the model each turn (every
    # tool stays callable) and the agent loads them on demand via the
    # `search_tools` meta-tool. `keep` overrides the always-exposed base set
    # (orchestration + task/schedule management + search_tools).
    tools_deferred_enabled: bool = False
    tools_deferred_keep: list[str] = field(default_factory=list)

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
        compaction = data.get("compaction", {})

        config = cls(
            model_provider=model.get("provider", cls.model_provider),
            model_name=model.get("name", cls.model_name),
            api_base=model.get("api_base", cls.api_base),
            api_key=model.get("api_key", cls.api_key),
            temperature=model.get("temperature", cls.temperature),
            max_tokens=model.get("max_tokens", cls.max_tokens),
            max_iterations=model.get("max_iterations", cls.max_iterations),
            knowledge_middleware=middleware.get("knowledge", True),
            knowledge_ingest_middleware=middleware.get("knowledge_ingest", True),
            audit_middleware=middleware.get("audit", True),
            memory_middleware=middleware.get("memory", True),
            tool_timeout_middleware=middleware.get("tool_timeout", True),
            tool_timeout_seconds=middleware.get("tool_timeout_seconds", cls.tool_timeout_seconds),
            knowledge_db_path=knowledge.get("db_path", cls.knowledge_db_path),
            embed_model=knowledge.get("embed_model", cls.embed_model),
            knowledge_top_k=knowledge.get("top_k", cls.knowledge_top_k),
            knowledge_search_mode=knowledge.get("search_mode", cls.knowledge_search_mode),
            knowledge_enrich_chunks=knowledge.get("enrich_chunks", cls.knowledge_enrich_chunks),
            workflows_enabled=(data.get("workflows") or {}).get("enabled", cls.workflows_enabled),
            workflow_dir=(data.get("workflows") or {}).get("dir", cls.workflow_dir),
            skills_enabled=(data.get("skills") or {}).get("enabled", cls.skills_enabled),
            skills_dir=(data.get("skills") or {}).get("dir", cls.skills_dir),
            skills_db_path=(data.get("skills") or {}).get("db_path", cls.skills_db_path),
            skills_top_k=(data.get("skills") or {}).get("top_k", cls.skills_top_k),
            tools_deferred_enabled=((data.get("tools") or {}).get("deferred") or {}).get(
                "enabled", cls.tools_deferred_enabled
            ),
            tools_deferred_keep=list(((data.get("tools") or {}).get("deferred") or {}).get("keep", []) or []),
            compaction_enabled=compaction.get("enabled", cls.compaction_enabled),
            compaction_trigger=compaction.get("trigger", cls.compaction_trigger),
            compaction_keep_messages=compaction.get("keep_messages", cls.compaction_keep_messages),
            compaction_model=compaction.get("model", cls.compaction_model),
            # `or {}` guards an empty `checkpoint:` block (YAML parses it to None).
            checkpoint_keep_per_thread=(data.get("checkpoint") or {}).get(
                "keep_per_thread", cls.checkpoint_keep_per_thread
            ),
            checkpoint_max_age_days=(data.get("checkpoint") or {}).get("max_age_days", cls.checkpoint_max_age_days),
            checkpoint_prune_interval_hours=(data.get("checkpoint") or {}).get(
                "prune_interval_hours", cls.checkpoint_prune_interval_hours
            ),
            # `or {}` guards an empty `routing:` block (YAML parses it to None).
            aux_model=(data.get("routing") or {}).get("aux_model", cls.aux_model),
        )

        for name in ("threat_scanner", "vuln_analyst", "intel_reporter"):
            if name in subagents:
                sub = subagents[name]
                setattr(
                    config,
                    name,
                    SubagentDef(
                        enabled=sub.get("enabled", True),
                        tools=sub.get("tools", getattr(config, name).tools),
                        max_turns=sub.get("max_turns", getattr(config, name).max_turns),
                    ),
                )

        return config
