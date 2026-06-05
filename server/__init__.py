"""
protoPen — AI security intelligence agent powered by local LLMs.

Monitors CVE feeds, security advisories, GitHub for the latest in security threats.
Uses LangGraph as the sole agent runtime.

Usage:
    python server.py                          # default port 7870
    python server.py --config path/to/config  # custom config
"""

import argparse
import asyncio
import json
import os
import re
from pathlib import Path
from typing import Any

from chat_ui import create_chat_app
from events import ACTIVITY_CONTEXT, EventBus
from events.sse import sse_event_stream
from runtime.state import STATE  # ADR 0023: the process runtime container
from server.chat import chat, _chat_langgraph_stream, _strip_think  # ADR 0023 phase 2b

# Repo root — bundled config / static / workflows / web dist live here. This
# module is now ``server/__init__.py`` (ADR 0023 package promotion), so the root
# is one directory up (``parents[1]``), not ``__file__``'s own dir.
_REPO_ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Agent setup
# ---------------------------------------------------------------------------


# Server→client SSE push channel (ADR 0003). Process-lifetime singleton:
# producers (A2A terminal hook, scheduler, inbox) publish; /api/events streams
# to connected consoles. Read-only — consoles never push back through it.
_event_bus = EventBus()


def _resolve_checkpoint_db(configured: str) -> str:
    """Pick a writable checkpoint DB path; fall back to ~/.protopen when the
    configured dir (default /sandbox) isn't creatable (e.g. local dev)."""
    import os

    candidate = Path(configured).expanduser()
    try:
        candidate.parent.mkdir(parents=True, exist_ok=True)
        if os.access(candidate.parent, os.W_OK):
            return str(candidate)
    except OSError:
        pass
    fallback = Path.home() / ".protopen" / "sessions.db"
    fallback.parent.mkdir(parents=True, exist_ok=True)
    return str(fallback)


def _build_checkpointer(configured_db: str):
    """Durable SQLite checkpointer (chat history survives restarts), falling back
    to an in-memory saver if SQLite init fails so a bad path never blocks boot.

    The graph compiles synchronously at boot, before the event loop, so we use a
    wrapped sync saver (graph/checkpointer.py) rather than the loop-bound
    AsyncSqliteSaver. Bound into the graph at compile time by the caller.
    """
    try:
        from graph.checkpointer import build_sqlite_checkpointer

        path = _resolve_checkpoint_db(configured_db)
        saver = build_sqlite_checkpointer(path)
        STATE.checkpoint_path = path  # the pruner sweeps this file
        print(f"[sessions] Persistent checkpointer: {path}")
        return saver
    except Exception as exc:
        from langgraph.checkpoint.memory import MemorySaver

        print(f"[sessions] SQLite checkpointer init failed ({exc}); using in-memory (history won't persist)")
        return MemorySaver()


async def _checkpoint_prune_loop() -> None:
    """Periodically trim the SQLite checkpoint DB (per-thread cap + age TTL).

    Reads the path + knobs from the live globals each pass so a config reload
    takes effect without restarting the loop. Failures are logged, never fatal.
    """
    from graph.checkpoint_prune import prune_checkpoints

    await asyncio.sleep(60)  # let boot settle before the first sweep
    while True:
        cfg = STATE.graph_config
        path = STATE.checkpoint_path
        interval_h = getattr(cfg, "checkpoint_prune_interval_hours", 0) if cfg else 0
        if path and cfg and interval_h > 0:
            try:
                # > 0 only: a negative max_age_days would invert the cutoff and
                # delete every thread. 0 / negative → no age TTL (cap-only sweep).
                max_age = cfg.checkpoint_max_age_days * 86400 if cfg.checkpoint_max_age_days > 0 else None
                res = await asyncio.to_thread(
                    prune_checkpoints,
                    path,
                    keep_per_thread=cfg.checkpoint_keep_per_thread,
                    max_age_seconds=max_age,
                )
                if res["threads_deleted"] or res["checkpoints_deleted"]:
                    print(
                        f"[checkpoint-prune] removed {res['threads_deleted']} idle thread(s), "
                        f"{res['checkpoints_deleted']} old checkpoint(s)"
                    )
            except Exception as exc:
                print(f"[checkpoint-prune] sweep failed: {exc}")
        await asyncio.sleep(max(1, interval_h) * 3600)


def _build_skills_index(config):
    """Build the SKILL.md skill index and seed it from disk (bundled config/skills/
    + a writable dir). Best-effort; never blocks boot."""
    if not getattr(config, "skills_enabled", True):
        return None
    try:
        import os

        from graph.skills import SkillsIndex, seed_index

        db = Path(getattr(config, "skills_db_path", "") or "/sandbox/skills.db").expanduser()
        try:
            db.parent.mkdir(parents=True, exist_ok=True)
            if not os.access(db.parent, os.W_OK):
                raise OSError
        except OSError:
            db = Path.home() / ".protopen" / "skills.db"
            db.parent.mkdir(parents=True, exist_ok=True)
        index = SkillsIndex(str(db))

        dirs: list[str] = []
        bundled = _REPO_ROOT / "config" / "skills"
        if bundled.is_dir():
            dirs.append(str(bundled))
        live = Path(getattr(config, "skills_dir", "") or "/sandbox/skills").expanduser()
        try:
            live.mkdir(parents=True, exist_ok=True)
            dirs.append(str(live))
        except OSError:
            pass
        n = seed_index(index, dirs)
        print(f"[skills] index ready at {db} ({n} skill(s) loaded)")
        return index
    except Exception as exc:
        print(f"[skills] index init failed ({exc}); skills disabled")
        return None


def _build_workflow_registry(config):
    """Load workflow recipes (ADR 0002) from the bundled repo workflows/ dir plus
    a writable dir (user/agent-emitted). Best-effort; never blocks boot."""
    if not getattr(config, "workflows_enabled", True):
        return None
    try:
        import os

        from graph.workflows.registry import WorkflowRegistry

        dirs: list[str] = []
        bundled = _REPO_ROOT / "workflows"
        if bundled.is_dir():
            dirs.append(str(bundled))
        writable = Path(getattr(config, "workflow_dir", "") or "/sandbox/workflows").expanduser()
        try:
            writable.mkdir(parents=True, exist_ok=True)
            if not os.access(writable, os.W_OK):
                raise OSError
        except OSError:
            writable = Path.home() / ".protopen" / "workflows"
            writable.mkdir(parents=True, exist_ok=True)
        dirs.append(str(writable))
        return WorkflowRegistry(dirs, writable_dir=str(writable))
    except Exception as exc:
        print(f"[workflows] registry init failed ({exc}); workflows disabled")
        return None


def _init_langgraph_agent():
    """Initialize the LangGraph agent backend."""

    from graph.agent import create_researcher_graph
    from graph.config import LangGraphConfig
    from sitrep import run_sitrep

    config_path = _REPO_ROOT / "config" / "langgraph-config.yaml"
    STATE.graph_config = LangGraphConfig.from_yaml(config_path)

    store = _get_store()

    # Persistent session checkpointer — bound into the graph at COMPILE time
    # below. A checkpointer set only in the invoke config is ignored by
    # LangGraph, which gave the chat amnesia (every turn started fresh).
    STATE.checkpointer = _build_checkpointer("/sandbox/knowledge/sessions.db")
    STATE.workflow_registry = _build_workflow_registry(STATE.graph_config)
    STATE.skills_index = _build_skills_index(STATE.graph_config)

    # Run startup sitrep — hardware, network, engagement status
    engagement_config = _REPO_ROOT / "config" / "engagement-config.json"
    status_block = run_sitrep(engagement_config)
    if status_block:
        print("[sitrep] Startup probe injected into system prompt")

    STATE.graph = create_researcher_graph(
        config=STATE.graph_config,
        knowledge_store=store,
        include_subagents=True,
        sitrep=status_block,
        checkpointer=STATE.checkpointer,
        workflow_registry=STATE.workflow_registry,
        skills_index=STATE.skills_index,
    )

    print(f"[researcher] LangGraph agent initialized (model: {STATE.graph_config.model_name})")


def _detect_vllm_model(api_base: str) -> str | None:
    """Query vLLM /v1/models to get the currently loaded model."""
    import httpx

    try:
        resp = httpx.get(f"{api_base}/models", timeout=5)
        data = resp.json().get("data", [])
        if data:
            return data[0]["id"]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Session commands
# ---------------------------------------------------------------------------

# Single source of truth for the chat slash-commands: drives both the /help
# table and the console composer autocomplete (GET /api/chat/commands).
_CHAT_COMMANDS: list[dict[str, str]] = [
    {"name": "new", "description": "Clear chat history + session", "usage": "/new"},
    {"name": "clear", "description": "Clear chat display (session preserved)", "usage": "/clear"},
    {"name": "think", "description": "Set reasoning effort (low/medium/high/off)", "usage": "/think <level>"},
    {"name": "compact", "description": "Force memory consolidation", "usage": "/compact"},
    {"name": "model", "description": "Show current model", "usage": "/model"},
    {"name": "tools", "description": "List registered tools", "usage": "/tools"},
    {"name": "topics", "description": "Show tracked security topics", "usage": "/topics"},
    {"name": "agenda", "description": "Show security intelligence agenda with stats", "usage": "/agenda"},
    {"name": "cves", "description": "Search stored CVEs and advisories", "usage": "/cves [query]"},
    {"name": "recent", "description": "Show recent findings", "usage": "/recent [n]"},
    {"name": "audit", "description": "Show recent audit log entries", "usage": "/audit [n]"},
    {"name": "intel", "description": "Generate intel digest and publish to Discord", "usage": "/intel"},
    {"name": "purple", "description": "Run purple team exercise (red+blue+ATT&CK report)", "usage": "/purple <scope>"},
    {
        "name": "goal",
        "description": "Set/show/clear a goal — loop until a verifier passes",
        "usage": "/goal <condition>  ·  /goal  ·  /goal clear",
    },
    {"name": "help", "description": "Show available commands", "usage": "/help"},
]


def _build_help_text() -> str:
    rows = "\n".join(f"| `{c['usage']}` | {c['description']} |" for c in _CHAT_COMMANDS)
    return "**protoPen commands:**\n\n| Command | Description |\n|---|---|\n" + rows


_HELP_TEXT = _build_help_text()

_THINK_LEVELS = {"low", "medium", "high", "off"}


def _msg(content: str) -> list[dict[str, Any]]:
    return [{"role": "assistant", "content": content}]


async def _handle_command(cmd: str, args: str, session_id: str) -> list[dict[str, Any]] | None:
    if cmd == "help":
        return _msg(_HELP_TEXT)

    if cmd == "clear":
        return [{"role": "assistant", "content": "", "metadata": {"_clear": True}}]

    if cmd == "new":
        return [{"role": "assistant", "content": "", "metadata": {"_new": True}}]

    if cmd == "model":
        model = STATE.graph_config.model_name if STATE.graph_config else "unknown"
        return _msg(f"**Model:** `{model}`")

    if cmd == "tools":
        from tools.lg_tools import get_all_tools

        tools = get_all_tools(_get_store())
        names = sorted(t.name for t in tools)
        listing = "\n".join(f"- `{n}`" for n in names)
        return _msg(f"**Registered tools ({len(names)}):**\n{listing}")

    if cmd == "think":
        level = args.strip().lower()
        if level not in _THINK_LEVELS:
            return _msg(f"Invalid level. Use one of: {', '.join(sorted(_THINK_LEVELS))}")
        return _msg(f"Reasoning effort set to **{level}**.")

    if cmd == "compact":
        return _msg("Memory consolidation is handled automatically by LangGraph checkpointing.")

    if cmd == "audit":
        from audit import audit_logger

        n = 20
        if args.strip().isdigit():
            n = int(args.strip())
        entries = audit_logger.get_recent(n, session_id=session_id)
        if not entries:
            return _msg("No audit entries found.")
        lines = []
        for e in entries:
            status = "ok" if e.get("success") else "FAIL"
            lines.append(
                f"- `{e['ts'][:19]}` **{e['tool']}** ({e['duration_ms']}ms) [{status}] — {e.get('result_summary', '')[:80]}"
            )
        return _msg(f"**Recent audit log ({len(entries)} entries):**\n" + "\n".join(lines))

    # Security-specific commands
    if cmd == "topics":
        return await _handle_topics_command()

    if cmd == "agenda":
        return await _handle_agenda_command()

    if cmd == "cves":
        return await _handle_cves_command(args)

    if cmd == "recent":
        return await _handle_recent_command(args)

    if cmd == "intel":
        return await _handle_intel_command(session_id)

    if cmd == "purple":
        return await _handle_purple_command(args, session_id)

    return None


# ---------------------------------------------------------------------------
# Purple team command
# ---------------------------------------------------------------------------


async def _handle_purple_command(
    args: str,
    session_id: str,
) -> list[dict[str, Any]]:
    """Run a purple team exercise via the playbook runner."""
    scope = args.strip()
    if not scope:
        return _msg(
            "**Usage:** `/purple <scope>`\n\n"
            "Example: `/purple 192.168.4.0/24`\n\n"
            "Runs the purple team exercise playbook: red team recon → "
            "blue team defensive checks → ATT&CK coverage matrix."
        )

    from playbooks.loader import load_playbook
    from playbooks.runner import run_playbook
    from playbooks.schema import StepStatus

    try:
        pb = load_playbook(
            "purple_team_exercise",
            {
                "target": scope,
                "exercise_name": f"purple-{session_id[:8]}",
            },
        )
    except FileNotFoundError:
        return _msg("❌ Purple team exercise playbook not found.")

    progress_lines = [f"## 🟣 Purple Team Exercise\n**Scope:** `{scope}`\n"]

    def on_step_complete(step):
        icon = "✅" if step.status == StepStatus.COMPLETED else "❌"
        progress_lines.append(f"{icon} **{step.name}** ({step.tool}.{step.action})")

    async def _dispatch(tool_name: str, action: str, params: dict) -> str:
        # Always dispatch directly — routing through the LLM adds latency
        # and risks the model wrapping / summarising raw tool output.
        from tools.lg_tools import get_combined_tools

        for t in get_combined_tools():
            if t.name == tool_name:
                return await t.ainvoke({"action": action, **params})
        return f"Error: Tool '{tool_name}' not found"

    await run_playbook(pb, _dispatch, on_step_complete=on_step_complete)

    # Build summary
    completed = sum(1 for s in pb.steps if s.status == StepStatus.COMPLETED)
    failed = sum(1 for s in pb.steps if s.status == StepStatus.FAILED)
    total = len(pb.steps)

    progress_lines.append(f"\n**Results:** {completed}/{total} steps completed, {failed} failed")

    # Extract coverage report from the last step if available
    report_step = next(
        (
            s
            for s in reversed(pb.steps)
            if s.tool == "purple_team" and s.action == "exercise_report" and s.status == StepStatus.COMPLETED
        ),
        None,
    )
    if report_step and report_step.output:
        try:
            raw = report_step.output.strip()
            # Strip markdown code fences the LLM may wrap around JSON
            if raw.startswith("```"):
                raw = re.sub(r"^```(?:json)?\s*\n?", "", raw)
                raw = re.sub(r"\n?```\s*$", "", raw)
            report = json.loads(raw)
            rate_pct = report.get("detection_rate_pct", report.get("detection_rate", 0) * 100)
            rating = report.get("rating", "UNKNOWN")
            progress_lines.append("\n### ATT&CK Coverage")
            progress_lines.append(f"**Rating:** {rating} ({rate_pct:.0f}% detection rate)")
            crit = report.get("critical_findings", [])
            high = report.get("high_findings", [])
            if crit:
                progress_lines.append(f"**Critical gaps:** {len(crit)}")
            if high:
                progress_lines.append(f"**High gaps:** {len(high)}")
            for f in crit[:5]:
                progress_lines.append(f"  - 🔴 {f['technique_id']} {f['technique_name']}")
            for f in high[:5]:
                progress_lines.append(f"  - 🟠 {f['technique_id']} {f['technique_name']}")
        except (json.JSONDecodeError, TypeError):
            progress_lines.append(f"\n### Raw Report Output\n```\n{report_step.output[:2000]}\n```")

    return _msg("\n".join(progress_lines))


# ---------------------------------------------------------------------------
# Security commands
# ---------------------------------------------------------------------------


def _get_store():
    if STATE.knowledge_store is None:
        from knowledge.store import KnowledgeStore

        STATE.knowledge_store = KnowledgeStore()
    return STATE.knowledge_store


async def _handle_topics_command() -> list[dict[str, Any]]:
    store = _get_store()
    topics = store.get_topics()
    if not topics:
        return _msg("No security topics configured. Ask me to add topics or use the security_memory tool.")

    lines = ["**Security Topics:**"]
    for t in topics:
        kw = json.loads(t.get("keywords", "[]"))
        kw_str = ", ".join(kw[:5]) if kw else ""
        scanned = t.get("last_scanned_at", "never") or "never"
        lines.append(
            f"- **{t['name']}** (P{t['priority']}) — {t.get('description', '')}\n"
            f"  Keywords: {kw_str} | Last scanned: {scanned}"
        )
    return _msg("\n".join(lines))


async def _handle_agenda_command() -> list[dict[str, Any]]:
    store = _get_store()
    stats = store.get_stats()
    topics = store.get_topics()

    lines = ["**Security Intelligence Agenda:**", ""]
    lines.append(f"CVEs tracked: {stats.get('cves', stats.get('papers', 0))}")
    lines.append(f"Findings stored: {stats.get('findings', 0)}")
    lines.append(f"Digests generated: {stats.get('digests', 0)}")
    lines.append(f"Advisories: {stats.get('advisories', 0)}")
    lines.append(f"Active topics: {len(topics)}")

    if topics:
        lines.append("\n**Topics by priority:**")
        for t in topics:
            lines.append(f"- P{t['priority']}: {t['name']}")

    return _msg("\n".join(lines))


async def _handle_cves_command(args: str) -> list[dict[str, Any]]:
    store = _get_store()
    query = args.strip()

    if query:
        results = store.hybrid_search(query, k=10, filter_table="cves")
        if not results:
            return _msg(f"No CVEs found matching '{query}'.")
        lines = [f"**CVEs matching '{query}':**"]
        for i, r in enumerate(results, 1):
            lines.append(f"{i}. [{r['source_id']}] {r['preview']}")
        return _msg("\n".join(lines))
    else:
        # Try cves table first, fall back to papers for backward compat
        cves = store.get_papers(limit=10)
        if not cves:
            return _msg("No CVEs in the knowledge base yet.")
        lines = ["**Recent CVEs:**"]
        for c in cves:
            sev = c.get("significance", c.get("severity", "?"))
            lines.append(f"- [{sev}] **{c['title']}** ({c['id']})")
        return _msg("\n".join(lines))


async def _handle_recent_command(args: str) -> list[dict[str, Any]]:
    store = _get_store()
    n = 10
    if args.strip().isdigit():
        n = int(args.strip())

    # Show recent CVEs + findings
    entries = store.get_papers(limit=n)
    lines = []

    if entries:
        lines.append("**Recent security findings:**")
        for e in entries[:n]:
            sev = e.get("significance", e.get("severity", "?"))
            lines.append(f"- [{sev}] {e['title']} ({e['id']}) — {e.get('discovered_at', '')[:10]}")

    if not lines:
        return _msg("No recent security activity.")

    return _msg("\n".join(lines))


async def _handle_intel_command(session_id: str) -> list[dict[str, Any]]:
    """Generate a security intelligence digest and publish to Discord via webhook."""
    import os

    webhook_url = os.environ.get("DISCORD_WEBHOOK_URL", "")
    if not webhook_url:
        return _msg("**Error:** DISCORD_WEBHOOK_URL not set.")

    # Gather security data for the digest
    store = _get_store()
    stats = store.get_stats()
    entries = store.get_papers(limit=15)
    topics = store.get_topics()

    # Build the security digest
    from datetime import datetime, timezone

    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    instance_name = os.environ.get("INSTANCE_NAME", "")
    instance_tag = f" [{instance_name}]" if instance_name else ""
    lines = [f"**🔒 protoPen{instance_tag} Security Intelligence Digest — {date_str}**\n"]

    if stats:
        lines.append(
            f"📊 **Knowledge Base:** {stats.get('cves', stats.get('papers', 0))} CVEs, "
            f"{stats.get('findings', 0)} findings, {stats.get('advisories', 0)} advisories\n"
        )

    if entries:
        lines.append("**🛡️ Recent Threats:**")
        for e in entries[:10]:
            sev = e.get("significance", e.get("severity", "?"))
            lines.append(f"• [{sev}] {e['title']}")
        lines.append("")

    if topics:
        lines.append("**🎯 Active Topics:** " + ", ".join(t["name"] for t in topics))

    lines.append(f"\n_Generated by protoPen{instance_tag} — protoLabs.studio_")

    digest_content = "\n".join(lines)

    # Publish via webhook
    import httpx

    webhook_name = f"protoPen [{instance_name}]" if instance_name else "protoPen"
    payload = {
        "username": webhook_name,
        "embeds": [
            {
                "title": f"🔒 Security Intelligence Digest — {date_str}",
                "description": digest_content[:4096],
                "color": 0xEF4444,
            }
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code in (200, 204):
                return _msg(f"**Published to Discord.**\n\n{digest_content}")
            return _msg(f"**Error:** Discord returned {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        return _msg(f"**Error publishing:** {e}")


# ---------------------------------------------------------------------------
# Chat function
# ---------------------------------------------------------------------------


def _build_agent_card_proto(card_data: dict, *, bearer: bool = False):
    """Build the A2A 1.0 ``AgentCard`` (proto) served at
    ``/.well-known/agent-card.json``, applying the protoLabs fleet conventions
    via ``protolabs_a2a.build_agent_card``.

    ``card_data`` is the plain dict (name / description / url / version / skills)
    — protoPen passes the ``AGENT_CARD`` defined in ``build_app``. protoPen's
    LangGraph stream emits only tool-call events, so only the tool-call-v1 is
    declared (not cost / confidence / worldstate-delta — it doesn't produce
    those). Auth is X-API-Key only, so ``bearer`` defaults to False.
    """
    import protolabs_a2a as pa
    from a2a.types import AgentSkill

    skills = [
        AgentSkill(
            id=s["id"],
            name=s["name"],
            description=s["description"],
            tags=s.get("tags", []),
            examples=s.get("examples", []),
        )
        for s in card_data["skills"]
    ]
    return pa.build_agent_card(
        name=card_data["name"],
        description=card_data["description"],
        url=card_data["url"],
        version=card_data["version"],
        skills=skills,
        extension_uris=[pa.TOOL_CALL_EXT_URI],
        bearer=bearer,
    )


# ---------------------------------------------------------------------------
# Settings callbacks
# ---------------------------------------------------------------------------


def _build_settings_callbacks() -> dict:
    def get_tools_list() -> str:
        from tools.lg_tools import get_all_tools

        tools = get_all_tools(_get_store())
        names = sorted(t.name for t in tools)
        return "\n".join(f"- `{n}`" for n in names) or "No tools registered."

    def get_model_info() -> str:
        if STATE.graph_config is not None:
            model = STATE.graph_config.model_name
            return f"**Model:** `{model}`\n\n**Backend:** LangGraph"
        return "**Model:** unknown"

    def get_provider_choices() -> list[str]:
        choices = []
        detected = _detect_vllm_model("http://host.docker.internal:8000/v1")
        if detected:
            choices.append(f"local: {detected}")
        choices.extend(
            [
                "claude: claude-sonnet-4-6",
                "claude: claude-haiku-4-5",
                "claude: claude-opus-4-6",
            ]
        )
        return choices

    def get_current_provider() -> str:
        if STATE.graph_config is not None:
            model = STATE.graph_config.model_name
        else:
            model = "unknown"
        if model.startswith("claude-"):
            current = f"claude: {model}"
        else:
            current = f"local: {model}"
        choices = get_provider_choices()
        if current not in choices and choices:
            return choices[0]
        return current

    def switch_provider(choice: str) -> str:
        if not choice:
            return "No provider selected."

        parts = choice.split(": ", 1)
        provider_type = parts[0]
        model_name = parts[1] if len(parts) > 1 else ""

        if STATE.graph_config is not None:
            if provider_type == "local":
                STATE.graph_config.model_provider = "vllm"
                detected = _detect_vllm_model("http://host.docker.internal:8000/v1")
                STATE.graph_config.model_name = detected or model_name
            elif provider_type == "claude":
                STATE.graph_config.model_provider = "openai"
                STATE.graph_config.model_name = model_name
            else:
                return f"**Error:** Unknown provider: {provider_type}"

            from graph.agent import create_researcher_graph

            STATE.graph = create_researcher_graph(
                config=STATE.graph_config,
                knowledge_store=_get_store(),
                include_subagents=True,
                checkpointer=STATE.checkpointer,
                workflow_registry=STATE.workflow_registry,
                skills_index=STATE.skills_index,
            )
            return f"**Switched to:** `{STATE.graph_config.model_name}` (graph rebuilt)"
        return "**Error:** LangGraph config not initialized."

    def get_subtitle() -> str:
        if STATE.graph_config is not None:
            display_model = STATE.graph_config.model_name
        else:
            display_model = "unknown"
        return f"**🔬 protoPen** &nbsp; `{display_model}`"

    def get_knowledge_stats() -> str:
        store = _get_store()
        stats = store.get_stats()
        if not stats:
            return "Knowledge base not initialized."
        lines = []
        for table, count in stats.items():
            lines.append(f"- {table}: {count}")
        return "\n".join(lines)

    return {
        "get_tools_list": get_tools_list,
        "get_model_info": get_model_info,
        "get_provider_choices": get_provider_choices,
        "get_current_provider": get_current_provider,
        "switch_provider": switch_provider,
        "get_subtitle": get_subtitle,
        "get_knowledge_stats": get_knowledge_stats,
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def _seed_topics():
    """Seed default research topics from config."""
    try:
        config_path = _REPO_ROOT / "config" / "security-config.json"
        if not config_path.exists():
            config_path = Path("/opt/protopen/config/security-config.json")
        if not config_path.exists():
            return

        research_config = json.loads(config_path.read_text())
        store = _get_store()
        existing = {t["name"] for t in store.get_topics(active_only=False)}

        for topic in research_config.get("topics", []):
            if topic["name"] not in existing:
                store.add_topic(
                    name=topic["name"],
                    keywords=topic.get("keywords", []),
                    priority=topic.get("priority", 2),
                )
        print(f"[researcher] Seeded {len(research_config.get('topics', []))} research topics")
    except Exception as e:
        print(f"[researcher] Topic seeding failed: {e}")


def _main():
    parser = argparse.ArgumentParser(description="protoPen Gradio UI")
    parser.add_argument("--port", type=int, default=7870)
    parser.add_argument("--config", type=str, default=None)
    parser.add_argument("--share", action="store_true")
    parser.add_argument(
        "--dump-openapi",
        type=str,
        default=None,
        metavar="PATH",
        help="Write the FastAPI OpenAPI spec to PATH and exit without serving. "
        "This is the source for docs/reference/api-endpoints.md — see "
        "scripts/gen_api_docs.py.",
    )
    args = parser.parse_args()

    # Initialize observability
    import tracing
    import metrics

    tracing.init()
    metrics.init()

    _init_langgraph_agent()

    # Seed default research topics
    _seed_topics()

    # Start Discord bot (watches for 🔬 reactions and @mentions)
    if os.environ.get("DISCORD_BOT_TOKEN"):
        from discord_bot import start_bot

        start_bot()

    blocks = create_chat_app(
        chat_fn=chat,
        title="🔬 protoPen",
        subtitle="",
        placeholder="Ask me about the latest security threats...",
        settings=_build_settings_callbacks(),
        pwa=True,
    )

    # ---------------------------------------------------------------------------
    # FastAPI + PWA static serving
    # ---------------------------------------------------------------------------
    import gradio as gr
    import uvicorn
    from fastapi import FastAPI
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    static_dir = _REPO_ROOT / "static"

    fastapi_app = FastAPI(title="protoPen — protoLabs")

    # Chat API endpoint (for evals and programmatic access)
    from pydantic import BaseModel as PydanticBaseModel

    class ChatRequest(PydanticBaseModel):
        message: str
        session_id: str = "api-default"

    @fastapi_app.post("/api/chat", summary="Chat (programmatic)")
    async def _api_chat(req: ChatRequest):
        result = await chat(req.message, req.session_id)
        # Extract assistant content
        parts = [m["content"] for m in result if m.get("role") == "assistant" and m.get("content")]
        return {"response": "\n\n".join(parts), "messages": result}

    # Server→client SSE push channel (ADR 0003). The console holds one of these
    # open for the app's lifetime; the server pushes unsolicited events (activity
    # messages, inbox items) that the request-scoped chat stream can't.
    @fastapi_app.get("/api/events", summary="Server→client event stream (SSE)")
    async def _api_events():
        from fastapi.responses import StreamingResponse

        return StreamingResponse(sse_event_stream(_event_bus.subscribe), media_type="text/event-stream")

    # OpenAI-compatible chat completions endpoint
    # Allows protoPen to be registered as a model in LiteLLM gateway / OpenWebUI
    import time as _time
    from fastapi.responses import StreamingResponse as _StreamingResponse

    @fastapi_app.post("/v1/chat/completions", summary="OpenAI-compatible chat completions")
    async def _openai_chat_completions(req: dict):
        messages = req.get("messages", [])
        user_msgs = [m for m in messages if m.get("role") == "user"]
        if not user_msgs:
            return {"error": "No user message provided"}, 400
        prompt = user_msgs[-1].get("content", "")
        session_id = f"openai-compat-{int(_time.time())}"
        stream = req.get("stream", False)

        result = await chat(prompt, session_id)
        parts = [m["content"] for m in result if m.get("role") == "assistant" and m.get("content")]
        content = "\n\n".join(parts)
        created = int(_time.time())
        completion_id = f"protopen-{session_id}"

        if stream:
            import json as _json

            async def _stream():
                chunk = {
                    "id": completion_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": "protopen",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"role": "assistant", "content": content},
                            "finish_reason": None,
                        }
                    ],
                }
                yield f"data: {_json.dumps(chunk)}\n\n"
                done_chunk = {
                    "id": completion_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": "protopen",
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                }
                yield f"data: {_json.dumps(done_chunk)}\n\n"
                yield "data: [DONE]\n\n"

            return _StreamingResponse(_stream(), media_type="text/event-stream")

        return {
            "id": completion_id,
            "object": "chat.completion",
            "created": created,
            "model": "protopen",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }

    @fastapi_app.get("/v1/models", summary="List models (OpenAI-compatible)")
    async def _openai_models():
        return {
            "object": "list",
            "data": [
                {
                    "id": "protopen",
                    "object": "model",
                    "created": 1774600000,
                    "owned_by": "protolabs",
                }
            ],
        }

    # ─── A2A protocol (a2a-sdk 1.0) ──────────────────────────────────────────
    # a2a-sdk mounts the full A2A 1.0 surface from the AgentCard + executor below
    # (JSON-RPC at /a2a, agent card at /.well-known/agent-card.json). AGENT_CARD
    # is the data source the proto card builder reads (name / description / url /
    # skills); see _build_agent_card_proto.

    _A2A_API_KEY = os.environ.get("PROTOPEN_API_KEY", os.environ.get("RESEARCHER_API_KEY", ""))

    AGENT_CARD = {
        "name": "protopen",
        "description": (
            "Autonomous pen testing and security intelligence agent. Combines hardware-in-the-loop "
            "security assessments (PortaPack H4M, Flipper Zero, WiFi Marauder, BlackArch) "
            "with threat intelligence capabilities (CVE feeds, security advisories, GitHub, knowledge store). "
            "Runs on a Steam Deck with attached RF/WiFi/RFID peripherals."
        ),
        # url must point to the JSON-RPC endpoint, not the server root
        "url": "http://steamdeck:7870/a2a",
        "provider": {"organization": "protoLabsAI"},
        "version": "2.0",
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/markdown"],
        "capabilities": {
            "stateTransitionHistory": False,
        },  # capabilities/extensions applied by _build_agent_card_proto()
        "securitySchemes": {
            "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        },
        "security": [{"apiKey": []}],
        "skills": [
            {
                "id": "passive_recon",
                "name": "Passive Reconnaissance",
                "description": (
                    "Perform passive reconnaissance on a target scope. Includes WiFi AP/station "
                    "enumeration, RF spectrum survey, network host discovery, and service "
                    "fingerprinting. No active probing or transmission — observation only."
                ),
                "tags": ["wifi", "rf", "network", "recon", "passive"],
                "examples": [
                    "Scan all WiFi networks in the 2.4 and 5 GHz bands",
                    "Discover hosts on 192.168.1.0/24 without sending probes",
                    "Survey RF spectrum around the office",
                ],
            },
            {
                "id": "active_pentest",
                "name": "Active Penetration Test",
                "description": (
                    "Execute controlled active exploitation against a defined scope. Includes "
                    "PMKID capture, service vulnerability scanning, RF signal replay, RFID "
                    "read/write. Requires active or redteam engagement mode. Returns findings "
                    "with severity ratings and evidence."
                ),
                "tags": ["pentest", "exploit", "wifi", "rfid", "rf", "active"],
                "examples": [
                    "Capture PMKID hashes from all WPA2 networks in range",
                    "Scan 10.0.0.0/24 for CVE-2024-XXXX",
                    "Replay captured RF signal on 433 MHz",
                ],
            },
            {
                "id": "security_report",
                "name": "Security Report",
                "description": (
                    "Generate a professional security assessment report from engagement "
                    "findings. Triages by severity, correlates across RF/WiFi/network domains, "
                    "identifies attack paths, and provides actionable remediation priorities."
                ),
                "tags": ["report", "assessment", "findings", "remediation"],
                "examples": [
                    "Generate a full assessment report for this engagement",
                    "Summarise findings by severity and map attack paths",
                ],
            },
            {
                "id": "threat_intel",
                "name": "Threat Intelligence",
                "description": (
                    "Research a security topic in depth: searches CVE databases, security advisories, "
                    "GitHub, web, and internal knowledge store. Returns a structured threat report."
                ),
                "tags": ["cve", "threat", "intel", "research", "advisory"],
                "examples": [
                    "Find critical CVEs affecting OpenSSH released in 2024",
                    "Research MITRE ATT&CK techniques used in recent ransomware campaigns",
                    "What vulnerabilities affect MikroTik RouterOS?",
                ],
            },
            {
                "id": "summarize",
                "name": "Summarize",
                "description": (
                    "Summarize recent CVEs, advisories, exploits, or threat intel from the "
                    "knowledge store. Optionally scoped to a topic or time window."
                ),
                "tags": ["summary", "cve", "advisory", "digest"],
                "examples": [
                    "Summarise the most critical CVEs from the last 7 days",
                    "What are the top threats to industrial control systems this month?",
                ],
            },
        ],
    }

    def _a2a_terminal(outcome) -> None:
        """A2A terminal hook (ADR 0003). Fired by ProtoPenExecutor with a
        TurnOutcome when a turn reaches a terminal state: when the turn belongs
        to the durable Activity thread, push the assistant's visible output to
        the event bus so connected consoles append it live. No-op otherwise."""
        if getattr(outcome, "context_id", "") != ACTIVITY_CONTEXT:
            return
        text = _strip_think(getattr(outcome, "text", "") or "")
        if not text.strip():
            return
        _event_bus.publish(
            "activity.message",
            {"role": "assistant", "text": text, "context_id": ACTIVITY_CONTEXT},
        )

    async def _operator_activity_list() -> dict:
        """Return the Activity thread's message history from the checkpointer
        (ADR 0003). The console loads this when opening the Activity surface."""
        messages: list[dict] = []
        if STATE.checkpointer is not None:
            thread_id = f"a2a:{ACTIVITY_CONTEXT}"
            try:
                tup = await STATE.checkpointer.aget_tuple({"configurable": {"thread_id": thread_id}})
                raw = (tup.checkpoint or {}).get("channel_values", {}).get("messages", []) if tup else []
            except Exception:
                print(f"[activity] failed to read thread {thread_id}")
                raw = []
            for m in raw:
                role = getattr(m, "type", "")
                content = getattr(m, "content", "")
                if not isinstance(content, str):
                    content = str(content)
                if role == "human":
                    messages.append({"role": "user", "content": content})
                elif role == "ai":
                    visible = _strip_think(content)
                    if visible.strip():
                        messages.append({"role": "assistant", "content": visible})
                # tool/system messages are omitted from the surface view
        return {"context_id": ACTIVITY_CONTEXT, "messages": messages}

    def _operator_workflows_list() -> dict:
        """List workflow recipes for the console's Workflows surface (ADR 0002)."""
        if STATE.workflow_registry is None:
            return {"workflows": []}
        return {"workflows": STATE.workflow_registry.list()}

    async def _operator_workflow_run(name: str, inputs: dict) -> dict:
        """Run a saved workflow from the operator console (ADR 0002)."""
        from graph.agent import run_manual_workflow

        return await run_manual_workflow(
            STATE.graph_config,
            STATE.workflow_registry,
            knowledge_store=_get_store(),
            name=name,
            inputs=inputs or {},
        )

    # Playbooks surface: browse the 23-recipe library + fire one manually.
    def _operator_playbooks_list() -> dict:
        from operator_api.playbooks import list_playbooks_for_console

        return list_playbooks_for_console()

    async def _operator_playbook_run(name: str, variables: dict) -> dict:
        from operator_api.playbooks import run_manual_playbook

        return await run_manual_playbook(name, variables or {})

    # a2a-sdk owns all protocol mechanics: JSON-RPC dispatch, SSE streaming, the
    # task lifecycle, and push delivery. ProtoPenExecutor bridges protoPen's
    # LangGraph stream onto it; protolabs_a2a builds the card + emits the
    # tool-call-v1 extension. Task + push-config state is durable (SQLite via
    # a2a_stores) and push callbacks are SSRF-guarded. The operator-console
    # surfaces (activity / workflows / playbooks) moved to operator_api below.
    import httpx

    from a2a.server.request_handlers import DefaultRequestHandler
    from a2a.server.routes.agent_card_routes import create_agent_card_routes
    from a2a.server.routes.fastapi_routes import add_a2a_routes_to_fastapi
    from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes

    import a2a_auth
    from a2a_executor import ProtoPenExecutor, set_terminal_hook
    from a2a_stores import build_a2a_stores, build_push_sender, initialize_a2a_stores

    set_terminal_hook(_a2a_terminal)  # ADR 0003: surface Activity turns

    # Request-time auth + origin enforcement (a2a-sdk advertises schemes on the
    # card but does not enforce them). protoPen uses X-API-Key only
    # (PROTOPEN_API_KEY / RESEARCHER_API_KEY); origin via A2A_ALLOWED_ORIGINS.
    a2a_auth.install(
        fastapi_app,
        bearer_token="",
        api_key=_A2A_API_KEY,
        allowed_origins_raw=os.environ.get("A2A_ALLOWED_ORIGINS", ""),
    )

    a2a_card = _build_agent_card_proto(AGENT_CARD)

    # Durable SQLite-backed task + push-config stores (survive restart; 24h TTL
    # sweep on tasks). The push-config store rejects SSRF callback URLs at
    # set-time; the matching push sender re-validates at send-time.
    task_store, push_config_store, task_db, push_db = build_a2a_stores()
    asyncio.run(initialize_a2a_stores(task_store, push_config_store))
    print(f"[a2a] durable stores ready (tasks={task_db}, push={push_db})")

    _a2a_push_client = httpx.AsyncClient(timeout=30)
    a2a_request_handler = DefaultRequestHandler(
        agent_executor=ProtoPenExecutor(_chat_langgraph_stream),
        task_store=task_store,
        agent_card=a2a_card,
        push_config_store=push_config_store,
        push_sender=build_push_sender(push_config_store, _a2a_push_client),
    )
    add_a2a_routes_to_fastapi(
        fastapi_app,
        agent_card_routes=create_agent_card_routes(a2a_card),
        jsonrpc_routes=create_jsonrpc_routes(a2a_request_handler, rpc_url="/a2a"),
    )
    print("[a2a] a2a-sdk routes mounted (JSON-RPC at /a2a, card at /.well-known/agent-card.json)")

    # Prometheus /metrics endpoint
    if metrics.is_enabled():
        try:
            from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
            from fastapi import Response as FastAPIResponse

            @fastapi_app.get("/metrics", include_in_schema=False)
            async def _prometheus_metrics():
                return FastAPIResponse(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
        except ImportError:
            pass

    if static_dir.exists():
        manifest_path = static_dir / "manifest.json"
        if manifest_path.exists():

            @fastapi_app.get("/manifest.json", include_in_schema=False)
            async def _serve_manifest() -> FileResponse:
                return FileResponse(str(manifest_path), media_type="application/manifest+json")

        sw_path = static_dir / "sw.js"
        if sw_path.exists():

            @fastapi_app.get("/sw.js", include_in_schema=False)
            async def _serve_sw() -> FileResponse:
                return FileResponse(
                    str(sw_path),
                    media_type="application/javascript",
                    headers={"Service-Worker-Allowed": "/"},
                )

        fastapi_app.mount("/static", StaticFiles(directory=str(static_dir)), name="ava-static")

    # --- React operator-console API + webview (ported from protoAgent #237) ---
    # Webview-only: the Tauri desktop wrapper is intentionally not ported.
    from operator_api.routes import register_operator_routes
    from operator_api.runtime import build_runtime_status as _build_operator_status
    from operator_api.subagents import (
        list_subagents as _operator_list_subagents,
        run_manual_subagent as _operator_run_manual_subagent,
        run_manual_subagent_batch as _operator_run_manual_subagent_batch,
    )
    from operator_api.web import mount_react_app

    def _operator_runtime_status():
        # protopen is configured via env/Infisical (no template setup wizard) and
        # has no cache_warmer/goal_controller — omit those (default None).
        return _build_operator_status(
            config=STATE.graph_config,
            setup_complete=True,
            graph_loaded=STATE.graph is not None,
            knowledge_store=STATE.knowledge_store,
            scheduler=_scheduler,
            skills_index=STATE.skills_index,
            goal_controller=STATE.goal_controller,
        )

    def _operator_subagent_list():
        return _operator_list_subagents(STATE.graph_config)

    async def _operator_subagent_run(req: dict):
        if STATE.graph is None:
            raise RuntimeError("agent graph is not loaded")
        return await _operator_run_manual_subagent(
            config=STATE.graph_config,
            knowledge_store=STATE.knowledge_store,
            scheduler=None,
            description=req.get("description", ""),
            prompt=req.get("prompt", ""),
            subagent_type=req.get("type") or req.get("subagent_type", "researcher"),
            emit_skill=bool(req.get("emit_skill", False)),
        )

    async def _operator_subagent_batch(req: dict):
        if STATE.graph is None:
            raise RuntimeError("agent graph is not loaded")
        return await _operator_run_manual_subagent_batch(
            config=STATE.graph_config,
            knowledge_store=STATE.knowledge_store,
            scheduler=None,
            tasks=req.get("tasks", []),
        )

    # Gate the operator API on the same key protoPen's A2A surface uses. When
    # unset (local dev), the operator routes stay open. The React console stores
    # this key and sends it as x-api-key; a 401 drives its login gate.
    import os as _os

    _operator_api_key = _os.environ.get("PROTOPEN_API_KEY", _os.environ.get("RESEARCHER_API_KEY", ""))

    # Local scheduler — sqlite + asyncio polling. Fires scheduled prompts at the
    # agent's own /a2a endpoint. protoPen is local-only (no remote backend).
    from scheduler import LocalScheduler

    _scheduler = LocalScheduler(
        agent_name=_os.environ.get("AGENT_NAME", "protopen"),
        invoke_url=f"http://127.0.0.1:{args.port}",
        api_key=_operator_api_key or None,
    )

    # Let the agent's schedule_task / list_schedules / cancel_schedule tools
    # reach the live scheduler (read lazily — the graph is already built).
    from tools.lg_tools import set_scheduler as _set_scheduler

    _set_scheduler(_scheduler)

    # Goal mode (autonomy): the chat-stream path checks /goal control messages +
    # runs the verifier-backed re-invocation loop. Off when goals_enabled=false.
    if getattr(STATE.graph_config, "goals_enabled", True):
        from graph.goals.controller import GoalController
        from graph.goals.store import GoalStore
        from tools.lg_tools import set_goal_controller as _set_goal_controller

        STATE.goal_controller = GoalController(STATE.graph_config, GoalStore())
        # Let the agent's set_goal tool reach the controller (read lazily).
        _set_goal_controller(STATE.goal_controller)

    # Let the agent's create_task / list_tasks / update_task / close_task tools
    # track long-running work in beads. Defaults to this repo's .beads/ store so
    # agent tasks and the console Beads panel share one tracker; override with
    # PROTOPEN_BEADS_PATH.
    from operator_api.beads import BeadsService as _BeadsService
    from tools.lg_tools import set_beads as _set_beads

    _beads_path = os.environ.get("PROTOPEN_BEADS_PATH") or str(_REPO_ROOT)
    _set_beads(_BeadsService(), _beads_path)

    @fastapi_app.on_event("startup")
    async def _start_scheduler():
        try:
            await _scheduler.start()
            print(f"[scheduler] local scheduler started ({_scheduler.path})")
        except Exception as exc:  # noqa: BLE001
            print(f"[scheduler] failed to start: {exc}")

        # Checkpoint pruner — periodic sweep to keep the SQLite history DB bounded.
        if (
            STATE.checkpoint_path
            and STATE.graph_config is not None
            and STATE.graph_config.checkpoint_prune_interval_hours > 0
        ):
            STATE.checkpoint_prune_task = asyncio.create_task(_checkpoint_prune_loop())

    @fastapi_app.on_event("shutdown")
    async def _stop_scheduler():
        try:
            await _scheduler.stop()
        except Exception as exc:  # noqa: BLE001
            print(f"[scheduler] failed to stop: {exc}")
        if STATE.checkpoint_prune_task is not None:
            STATE.checkpoint_prune_task.cancel()

    # Monitor view: surface the live engagement + findings (protoPen-specific).
    from operator_api.engagement import (
        build_engagement_status as _build_engagement_status,
        control_engagement as _control_engagement,
        generate_engagement_report as _generate_engagement_report,
        read_engagement_report as _read_engagement_report,
    )

    def _operator_engagement_manager():
        from tools.lg_tools import get_engagement_manager

        return get_engagement_manager()

    def _operator_engagement_status():
        try:
            return _build_engagement_status(_operator_engagement_manager())
        except Exception:
            return _build_engagement_status(None)

    def _operator_engagement_report():
        try:
            return _read_engagement_report(_operator_engagement_manager())
        except Exception:
            return _read_engagement_report(None)

    def _operator_engagement_report_generate():
        return _generate_engagement_report(_operator_engagement_manager())

    def _operator_engagement_control(payload: dict) -> dict:
        # Acts on the SAME EngagementManager singleton the enforcement middleware
        # checks, so starting one here unblocks the agent's engagement-gated tools
        # without depending on the agent calling its own engagement tool.
        return _control_engagement(_operator_engagement_manager(), payload)

    # Knowledge surface: hybrid search over the threat-intel store.
    from operator_api.knowledge import search_knowledge as _search_knowledge

    def _operator_knowledge_search(query: str, k: int = 10, table: str | None = None):
        return _search_knowledge(_get_store(), query=query, k=k, table=table)

    # Skills surface: browse the memory layer (learned methodology).
    def _operator_skills_list(query: str = ""):
        from operator_api.skills import list_skills_for_console

        return list_skills_for_console(STATE.skills_index, query)

    # Goals surface: list active/past goals + clear one (autonomy layer).
    def _operator_goals_list():
        if STATE.goal_controller is None:
            return {"enabled": False, "goals": []}
        return {"enabled": True, "goals": [g.to_dict() for g in STATE.goal_controller.store.all()]}

    def _operator_goal_clear(session_id: str):
        if STATE.goal_controller is None:
            return {"cleared": False}
        return {"cleared": STATE.goal_controller.store.clear(session_id)}

    # Targets & Intel surface: browse discovered hosts, past engagements, and
    # search across everything captured (read-only over the existing stores).
    from operator_api import intel as _intel

    def _operator_target_store():
        # Degrade gracefully so the console shows "no targets" rather than 500ing,
        # but log unexpected faults instead of masking them silently.
        try:
            from tools.lg_tools import get_target_store

            return get_target_store()
        except Exception as exc:  # noqa: BLE001
            print(f"[targets] store unavailable: {exc}")
            return None

    def _operator_targets_list(q: str = "", device_type: str = "", limit: int = 50):
        return _intel.list_targets(_operator_target_store(), query=q, device_type=device_type, limit=limit)

    def _operator_target_get(host_id: int):
        return _intel.get_target(_operator_target_store(), host_id)

    def _operator_engagements_list():
        mgr = _operator_engagement_manager()
        active = getattr(mgr, "active_engagement", None) or {}
        workspace_root = ""
        try:
            workspace_root = str(getattr(mgr, "_workspace_root", "") or "")
        except Exception:
            workspace_root = ""
        return _intel.list_engagement_history(workspace_root, active_name=active.get("name", ""))

    def _operator_intel_search(q: str, k: int = 20):
        return _intel.search_intel(_operator_target_store(), _get_store(), query=q, k=k)

    # Audit surface: recent tool-execution trail.
    from audit import audit_logger as _audit_logger
    from operator_api.audit import recent_audit as _recent_audit

    def _operator_audit_recent(n: int = 50, session_id: str | None = None):
        return _recent_audit(_audit_logger, n=n, session_id=session_id)

    # Live agent monitoring: launch manual subagents as tracked, cancellable
    # background tasks (the synchronous /api/subagents/* path stays available).
    from operator_api.agent_runtime import agent_registry as _agent_registry

    def _operator_agent_launch(req: dict):
        if STATE.graph is None:
            raise RuntimeError("agent graph is not loaded")
        subagent_type = req.get("type") or req.get("subagent_type", "researcher")

        def _factory():
            return _operator_run_manual_subagent(
                config=STATE.graph_config,
                knowledge_store=STATE.knowledge_store,
                scheduler=None,
                description=req.get("description", ""),
                prompt=req.get("prompt", ""),
                subagent_type=subagent_type,
                emit_skill=bool(req.get("emit_skill", False)),
            )

        return _agent_registry.launch(
            _factory,
            agent_type=subagent_type,
            description=req.get("description", "") or req.get("prompt", "")[:80],
        )

    # Scheduler management — list/create/cancel jobs on the local scheduler.
    def _operator_scheduler_list():
        return {"jobs": [j.as_dict() for j in _scheduler.list_jobs()], "backend": _scheduler.name}

    def _operator_scheduler_add(req: dict):
        job = _scheduler.add_job(req["prompt"], req["schedule"], job_id=req.get("job_id"))
        return job.as_dict()

    def _operator_scheduler_cancel(job_id: str):
        return {"canceled": _scheduler.cancel_job(job_id)}

    def _operator_chat_commands() -> dict:
        """Slash commands the chat understands — drives the composer autocomplete."""
        return {"commands": _CHAT_COMMANDS}

    register_operator_routes(
        fastapi_app,
        runtime_status=_operator_runtime_status,
        subagent_list=_operator_subagent_list,
        subagent_run=_operator_subagent_run,
        subagent_batch=_operator_subagent_batch,
        engagement_status=_operator_engagement_status,
        engagement_report=_operator_engagement_report,
        engagement_report_generate=_operator_engagement_report_generate,
        engagement_control=_operator_engagement_control,
        knowledge_search=_operator_knowledge_search,
        skills_list=_operator_skills_list,
        goals_list=_operator_goals_list,
        goal_clear=_operator_goal_clear,
        targets_list=_operator_targets_list,
        target_get=_operator_target_get,
        engagements_list=_operator_engagements_list,
        intel_search=_operator_intel_search,
        audit_recent=_operator_audit_recent,
        agent_launch=_operator_agent_launch,
        agent_list=lambda: _agent_registry.snapshot(),
        agent_get=lambda task_id: _agent_registry.get(task_id),
        agent_cancel=lambda task_id: _agent_registry.cancel(task_id),
        scheduler_list=_operator_scheduler_list,
        scheduler_add=_operator_scheduler_add,
        scheduler_cancel=_operator_scheduler_cancel,
        chat_commands=_operator_chat_commands,
        # Surfaces relocated off the hand-rolled A2A handler in the a2a-sdk
        # migration (#140) — same operator-key gate, now on the operator router.
        activity_list=_operator_activity_list,  # ADR 0003: Activity thread history
        workflows_list=_operator_workflows_list,  # ADR 0002: Workflows surface
        workflows_run=_operator_workflow_run,
        playbooks_list=_operator_playbooks_list,
        playbooks_run=_operator_playbook_run,
        api_key=_operator_api_key,
    )

    _web_dist = _REPO_ROOT / "apps" / "web" / "dist"
    if mount_react_app(fastapi_app, _web_dist):
        print("[protoPen] React operator console mounted at /app")

    # Spec dump: emit the fully-assembled REST surface (chat, /v1, operator API)
    # and exit before the Gradio mount and uvicorn — the spec, not the server.
    if args.dump_openapi:
        spec = fastapi_app.openapi()
        out = Path(args.dump_openapi)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n")
        print(f"[protoPen] Wrote OpenAPI spec to {out} ({len(spec.get('paths', {}))} paths)")
        return

    app = gr.mount_gradio_app(
        fastapi_app,
        blocks,
        path="/",
        footer_links=[],
        favicon_path=str(static_dir / "favicon.svg") if (static_dir / "favicon.svg").exists() else None,
    )

    print(f"[protoPen] Starting on http://0.0.0.0:{args.port}")
    uvicorn.run(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    _main()
