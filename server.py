"""
protoPen — AI security intelligence agent powered by local LLMs.

Monitors CVE feeds, security advisories, GitHub for the latest in security threats.
Supports two agent backends: nanobot (legacy) and LangGraph (new).

Usage:
    python server.py                          # default port 7870
    AGENT_BACKEND=langgraph python server.py  # use LangGraph backend
    python server.py --config path/to/config  # custom config
"""

import argparse
import asyncio
import contextvars
import json
import os
import re
import time
from pathlib import Path
from typing import Any

from chat_ui import create_chat_app

# Agent backend selection
_BACKEND = os.environ.get("AGENT_BACKEND", "nanobot")

# ---------------------------------------------------------------------------
# Agent setup
# ---------------------------------------------------------------------------

_agent = None       # nanobot AgentLoop (when AGENT_BACKEND=nanobot)
_graph = None       # LangGraph compiled graph (when AGENT_BACKEND=langgraph)
_graph_config = None  # LangGraphConfig
_checkpointer = None  # LangGraph MemorySaver for session persistence
_config = None


def _patch_identity():
    """Replace nanobot's default identity header with protoPen branding."""
    from nanobot.agent.context import ContextBuilder

    _original_get_identity = ContextBuilder._get_identity

    def _patched_get_identity(self):
        original = _original_get_identity(self)
        # Replace the nanobot header
        original = original.replace("# nanobot 🐈", "# protoPen 🔬")
        original = original.replace(
            "You are nanobot, a helpful AI assistant.",
            "You are protoPen, an autonomous AI research assistant built by protoLabs.",
        )
        original = original.replace("## nanobot Guidelines", "## Guidelines")
        return original

    ContextBuilder._get_identity = _patched_get_identity


def _init_agent(config_path: str | None = None):
    """Initialize nanobot agent loop."""
    global _agent, _config

    from nanobot.agent.loop import AgentLoop
    from nanobot.bus.queue import MessageBus
    from nanobot.config.loader import load_config, set_config_path
    from nanobot.config.paths import get_cron_dir
    from nanobot.cron.service import CronService
    from nanobot.utils.helpers import sync_workspace_templates

    if config_path:
        p = Path(config_path).expanduser().resolve()
        set_config_path(p)

    _config = load_config(Path(config_path) if config_path else None)
    sync_workspace_templates(_config.workspace_path)

    bus = MessageBus()
    provider = _make_provider(_config)

    cron = CronService(get_cron_dir() / "jobs.json")

    _agent = AgentLoop(
        bus=bus,
        provider=provider,
        workspace=_config.workspace_path,
        model=None,
        max_iterations=_config.agents.defaults.max_tool_iterations,
        context_window_tokens=_config.agents.defaults.context_window_tokens,
        web_search_config=_config.tools.web.search,
        web_proxy=_config.tools.web.proxy or None,
        exec_config=_config.tools.exec,
        cron_service=cron,
        restrict_to_workspace=_config.tools.restrict_to_workspace,
        mcp_servers=_config.tools.mcp_servers,
        channels_config=_config.channels,
    )

    # Override nanobot's default identity with protoPen branding
    _patch_identity()


def _init_langgraph_agent():
    """Initialize the LangGraph agent backend."""
    global _graph, _graph_config, _checkpointer

    from graph.agent import create_researcher_graph
    from graph.config import LangGraphConfig
    from sitrep import run_sitrep

    config_path = Path(__file__).parent / "config" / "langgraph-config.yaml"
    _graph_config = LangGraphConfig.from_yaml(config_path)

    store = _get_store()

    # Persistent session checkpointer — survives restarts
    _sessions_db = Path("/sandbox/knowledge/sessions.db")
    _sessions_db.parent.mkdir(parents=True, exist_ok=True)
    try:
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
        _checkpointer = AsyncSqliteSaver.from_conn_string(str(_sessions_db))
        print(f"[sessions] Persistent checkpointer: {_sessions_db}")
    except ImportError:
        from langgraph.checkpoint.memory import MemorySaver
        _checkpointer = MemorySaver()
        print("[sessions] Falling back to in-memory checkpointer")

    # Run startup sitrep — hardware, network, engagement status
    engagement_config = Path(__file__).parent / "config" / "engagement-config.json"
    status_block = run_sitrep(engagement_config)
    if status_block:
        print(f"[sitrep] Startup probe injected into system prompt")

    _graph = create_researcher_graph(
        config=_graph_config,
        knowledge_store=store,
        include_subagents=True,
        sitrep=status_block,
    )

    print(f"[researcher] LangGraph agent initialized (model: {_graph_config.model_name})")


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


def _make_provider(config):
    """Create provider — auto-detects vLLM model."""
    from nanobot.providers.base import GenerationSettings
    from nanobot.providers.litellm_provider import LiteLLMProvider

    model = config.agents.defaults.model
    provider_name = config.get_provider_name(model)
    p = config.get_provider(model)
    api_base = config.get_api_base(model)

    if api_base and (model == "auto" or provider_name in ("vllm", "ollama")):
        detected = _detect_vllm_model(api_base)
        if detected:
            model = detected

    # Gateway is OpenAI-compatible — tell nanobot/litellm to use openai protocol
    effective_provider = provider_name
    api_key = p.api_key if p else None
    if provider_name in ("cliproxy", "gateway"):
        effective_provider = "openai"
        api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        os.environ["OPENAI_API_KEY"] = api_key

    provider = LiteLLMProvider(
        api_key=api_key,
        api_base=api_base,
        default_model=model,
        extra_headers=p.extra_headers if p else None,
        provider_name=effective_provider,
    )

    defaults = config.agents.defaults
    provider.generation = GenerationSettings(
        temperature=defaults.temperature,
        max_tokens=defaults.max_tokens,
        reasoning_effort=defaults.reasoning_effort,
    )
    return provider


# ---------------------------------------------------------------------------
# Session commands
# ---------------------------------------------------------------------------

_HELP_TEXT = """\
**protoPen commands:**
| Command | Description |
|---------|-------------|
| `/new` | Clear chat history + session |
| `/clear` | Clear chat display (session preserved) |
| `/think <level>` | Set reasoning effort (low/medium/high/off) |
| `/compact` | Force memory consolidation |
| `/model` | Show current model |
| `/tools` | List registered tools |
| `/topics` | Show tracked security topics |
| `/agenda` | Show security intelligence agenda with stats |
| `/cves [query]` | Search stored CVEs and advisories |
| `/recent [n]` | Show recent findings |
| `/audit [n]` | Show recent audit log entries |
| `/lab on\\|off\\|status` | Toggle lab mode (GPU experiment runner) |
| `/intel` | Generate security intelligence digest and publish to Discord |
| `/purple <scope>` | Run purple team exercise (red+blue+ATT&CK report) |
| `/help` | Show this help |
"""

_THINK_LEVELS = {"low", "medium", "high", "off"}


def _msg(content: str) -> list[dict[str, Any]]:
    return [{"role": "assistant", "content": content}]


async def _handle_command(
    cmd: str, args: str, session_id: str
) -> list[dict[str, Any]] | None:
    if cmd == "help":
        return _msg(_HELP_TEXT)

    if cmd == "clear":
        return [{"role": "assistant", "content": "", "metadata": {"_clear": True}}]

    if cmd == "new":
        session_key = f"gradio:{session_id}"
        session = _agent.sessions.get_or_create(session_key)
        session.clear()
        _agent.sessions.save(session)
        return [{"role": "assistant", "content": "", "metadata": {"_new": True}}]

    if cmd == "model":
        return _msg(f"**Model:** `{_agent.model}`")

    if cmd == "tools":
        names = _agent.tools.tool_names
        listing = "\n".join(f"- `{n}`" for n in sorted(names))
        return _msg(f"**Registered tools ({len(names)}):**\n{listing}")

    if cmd == "think":
        level = args.strip().lower()
        if level not in _THINK_LEVELS:
            return _msg(f"Invalid level. Use one of: {', '.join(sorted(_THINK_LEVELS))}")
        val = None if level == "off" else level
        _agent.provider.generation.reasoning_effort = val
        return _msg(f"Reasoning effort set to **{level}**.")

    if cmd == "compact":
        session_key = f"gradio:{session_id}"
        session = _agent.sessions.get_or_create(session_key)
        await _agent.memory_consolidator.maybe_consolidate_by_tokens(session)
        return _msg("Memory consolidation complete.")

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

    if cmd == "lab":
        return await _handle_lab_command(args)

    if cmd == "intel":
        return await _handle_intel_command(session_id)

    if cmd == "purple":
        return await _handle_purple_command(args, session_id)

    return None


# ---------------------------------------------------------------------------
# Purple team command
# ---------------------------------------------------------------------------


async def _handle_purple_command(
    args: str, session_id: str,
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
        pb = load_playbook("purple_team_exercise", {
            "target": scope,
            "exercise_name": f"purple-{session_id[:8]}",
        })
    except FileNotFoundError:
        return _msg("❌ Purple team exercise playbook not found.")

    progress_lines = [f"## 🟣 Purple Team Exercise\n**Scope:** `{scope}`\n"]

    def on_step_complete(step):
        icon = "✅" if step.status == StepStatus.COMPLETED else "❌"
        progress_lines.append(f"{icon} **{step.name}** ({step.tool}.{step.action})")

    async def _dispatch(tool_name: str, action: str, params: dict) -> str:
        if _BACKEND == "langgraph" and _graph is not None:
            prompt = (
                f"Run the {tool_name} tool with action={action} "
                f"and parameters: {json.dumps(params)}. "
                f"Return only the raw tool output."
            )
            results = await _chat_langgraph(prompt, session_id)
            return results[-1].get("content", "") if results else ""
        # Direct tool dispatch fallback
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

    progress_lines.append(
        f"\n**Results:** {completed}/{total} steps completed, {failed} failed"
    )

    # Extract coverage report from the last step if available
    report_step = next(
        (s for s in reversed(pb.steps)
         if s.tool == "purple_team" and s.action == "exercise_report"
         and s.status == StepStatus.COMPLETED),
        None,
    )
    if report_step and report_step.output:
        try:
            report = json.loads(report_step.output)
            rate = report.get("detection_rate", 0)
            rating = report.get("rating", "UNKNOWN")
            progress_lines.append(f"\n### ATT&CK Coverage")
            progress_lines.append(
                f"**Rating:** {rating} ({rate:.0%} detection rate)"
            )
            if report.get("critical_findings"):
                progress_lines.append(
                    f"**Critical gaps:** {len(report['critical_findings'])}"
                )
        except (json.JSONDecodeError, TypeError):
            progress_lines.append(
                f"\n### Raw Report Output\n```\n"
                f"{report_step.output[:2000]}\n```"
            )

    return _msg("\n".join(progress_lines))


# ---------------------------------------------------------------------------
# Security commands
# ---------------------------------------------------------------------------

_knowledge_store = None


def _get_store():
    global _knowledge_store
    if _knowledge_store is None:
        from knowledge.store import KnowledgeStore
        _knowledge_store = KnowledgeStore()
    return _knowledge_store


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
        lines.append(f"📊 **Knowledge Base:** {stats.get('cves', stats.get('papers', 0))} CVEs, "
                     f"{stats.get('findings', 0)} findings, {stats.get('advisories', 0)} advisories\n")

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
        "embeds": [{
            "title": f"🔒 Security Intelligence Digest — {date_str}",
            "description": digest_content[:4096],
            "color": 0xef4444,
        }],
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
# Lab mode — toggleable GPU experiment runner
# ---------------------------------------------------------------------------

_lab_mode = False
_lab_tool = None


def _is_lab_available() -> bool:
    """Check if GPU/lab dependencies are available."""
    import os
    return os.path.exists("/opt/llama-factory") or os.environ.get("LAB_GPU") is not None


async def _handle_lab_command(args: str) -> list[dict[str, Any]]:
    global _lab_mode, _lab_tool
    subcmd = args.strip().lower() or "status"

    if subcmd == "on":
        if _lab_mode:
            return _msg("Lab mode is already **on**.")
        if not _is_lab_available():
            return _msg(
                "**Lab mode unavailable.** Run with the lab profile:\n"
                "```\ndocker compose --profile lab up --build\n```"
            )
        from tools.lab_bench import LabBenchTool
        _lab_tool = LabBenchTool()
        _agent.tools.register(_lab_tool)
        _lab_mode = True

        import os
        gpu = os.environ.get("LAB_GPU", "1")
        return _msg(
            f"**Lab mode ON.** `lab_bench` tool registered.\n"
            f"GPU: `CUDA_VISIBLE_DEVICES={gpu}`\n"
            f"Models: Qwen3.5-0.8B, Qwen3.5-2B\n"
            f"Stack: LLaMA-Factory (LoRA DPO)\n\n"
            f"Use `lab_bench` tool to init and run experiments."
        )

    if subcmd == "off":
        if not _lab_mode:
            return _msg("Lab mode is already **off**.")
        if _lab_tool:
            _agent.tools.unregister("lab_bench")
            _lab_tool = None
        _lab_mode = False
        return _msg("**Lab mode OFF.** `lab_bench` tool unregistered.")

    if subcmd == "status":
        if not _lab_mode:
            return _msg("Lab mode is **off**. Use `/lab on` to enable.")
        if _lab_tool:
            status = _lab_tool._runner.get_status()
            return _msg(f"Lab mode is **on**.\n\n{status}")
        return _msg("Lab mode is **on** (no experiments yet).")

    return _msg("Usage: `/lab on`, `/lab off`, `/lab status`")


# ---------------------------------------------------------------------------
# Audit logging wrapper
# ---------------------------------------------------------------------------

_current_session_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_current_session_id", default=""
)


def _install_audit_wrapper():
    from audit import audit_logger
    import tracing
    import metrics

    original_execute = _agent.tools.execute

    # Map tool names to security phase spans for Langfuse
    _TOOL_PHASE_MAP = {
        "discord_feed": "threat_scanner",
        "cve_search": "threat_scanner",
        "security_feeds": "threat_scanner",
        "github_trending": "threat_scanner",
        "web_search": "threat_scanner",
        "web_fetch": "threat_scanner",
        "browser": "vuln_analyst",
        "security_memory": "vuln_analyst",
        "message": "intel_reporter",
    }

    async def _audited_execute(name: str, params: dict[str, Any]) -> str:
        session_id = _current_session_id.get("")
        t0 = time.monotonic()
        phase = _TOOL_PHASE_MAP.get(name, "general")

        # Capture message tool content so it can be surfaced in the chat
        if name == "message":
            content = params.get("content", "")
            if content:
                try:
                    captured = _message_tool_content.get([])
                    captured.append(content)
                except LookupError:
                    pass

        try:
            result = await original_execute(name, params)
            duration_ms = int((time.monotonic() - t0) * 1000)
            success = not (isinstance(result, str) and result.startswith("Error"))
            result_summary = result[:200] if isinstance(result, str) else str(result)[:200]
            audit_logger.log(
                session_id=session_id, tool=name, args=params,
                result_summary=result_summary, duration_ms=duration_ms, success=success,
            )
            tracing.trace_tool_call(
                tool_name=f"{phase}:{name}", args=params, result=result_summary,
                duration_ms=duration_ms, success=success, session_id=session_id,
            )
            metrics.record_tool_call(name, success, duration_ms / 1000)
            return result
        except Exception as exc:
            duration_ms = int((time.monotonic() - t0) * 1000)
            audit_logger.log(
                session_id=session_id, tool=name, args=params,
                result_summary=str(exc)[:200], duration_ms=duration_ms, success=False,
            )
            tracing.trace_tool_call(
                tool_name=f"{phase}:{name}", args=params, result=str(exc)[:200],
                duration_ms=duration_ms, success=False, session_id=session_id,
            )
            metrics.record_tool_call(name, False, duration_ms / 1000)
            raise

    _agent.tools.execute = _audited_execute


# ---------------------------------------------------------------------------
# Chat function
# ---------------------------------------------------------------------------


def _strip_think(text: str) -> str:
    text = re.sub(r"<think>[\s\S]*?</think>", "", text)
    text = re.sub(r"</think>\s*", "", text)
    return text.strip()


# Captured message tool content — nanobot sends final responses via message() tool
_message_tool_content: contextvars.ContextVar[list[str]] = contextvars.ContextVar(
    "_message_tool_content", default=[]
)


import queue as _queue_mod


async def chat(message: str, session_id: str) -> list[dict[str, Any]]:
    """Route to the active backend."""
    # Slash commands are handled identically by both backends
    stripped = message.strip()
    if stripped.startswith("/"):
        parts = stripped.split(None, 1)
        cmd = parts[0][1:].lower()
        args = parts[1] if len(parts) > 1 else ""
        result = await _handle_command(cmd, args, session_id)
        if result is not None:
            return result

    # Route to backend
    if _BACKEND == "langgraph" and _graph is not None:
        return await _chat_langgraph(message, session_id)
    else:
        return await _chat_nanobot(message, session_id)


async def _chat_nanobot(message: str, session_id: str) -> list[dict[str, Any]]:
    """Process via nanobot's agent loop (legacy backend)."""
    import tracing
    token = _current_session_id.set(session_id)
    msg_token = _message_tool_content.set([])
    tracing.start_trace(session_id=session_id, name="researcher-chat", metadata={"message_preview": message[:100]})
    try:
        progress_messages: list[dict] = []

        async def on_progress(content: str, *, tool_hint: bool = False) -> None:
            content = _strip_think(content)
            if not content:
                return
            if tool_hint:
                progress_messages.append({
                    "role": "assistant",
                    "metadata": {"title": f"🔧 {content}"},
                    "content": "",
                })
            else:
                progress_messages.append({
                    "role": "assistant",
                    "metadata": {"title": "💭 Thinking"},
                    "content": content,
                })

        response = await _agent.process_direct(
            content=message,
            session_key=f"gradio:{session_id}",
            channel="gradio",
            chat_id=session_id,
            on_progress=on_progress,
        )

        if hasattr(response, "content"):
            response = response.content
        response = _strip_think(response or "")

        captured = _message_tool_content.get([])
        if not response and captured:
            response = "\n\n".join(captured)

        return [*progress_messages, {"role": "assistant", "content": response}]
    finally:
        tracing.end_trace()
        _current_session_id.reset(token)
        _message_tool_content.reset(msg_token)


async def _chat_langgraph(message: str, session_id: str) -> list[dict[str, Any]]:
    """Process via LangGraph agent backend."""
    import tracing
    from langchain_core.messages import HumanMessage, AIMessage

    tracing.start_trace(session_id=session_id, name="researcher-chat-lg", metadata={"message_preview": message[:100]})
    try:
        # Invoke the graph with session-scoped checkpointing
        config = {"configurable": {"thread_id": f"gradio:{session_id}"}}
        if _checkpointer:
            config["checkpointer"] = _checkpointer

        result = await _graph.ainvoke(
            {"messages": [HumanMessage(content=message)], "session_id": session_id},
            config=config,
        )

        # Extract the last AI message
        messages = result.get("messages", [])
        response = ""
        for msg in reversed(messages):
            if isinstance(msg, AIMessage) and msg.content:
                response = msg.content if isinstance(msg.content, str) else str(msg.content)
                break

        response = _strip_think(response)
        return [{"role": "assistant", "content": response}]
    except Exception as e:
        return [{"role": "assistant", "content": f"**Error:** {e}"}]
    finally:
        tracing.end_trace()


async def _chat_langgraph_stream(message: str, session_id: str):
    """Async generator that yields (event_type, payload) tuples via astream_events.

    event_type is one of: "status", "tool_start", "tool_end", "text", "done", "error"
    """
    from langchain_core.messages import HumanMessage

    config = {"configurable": {"thread_id": f"gradio:{session_id}"}}
    if _checkpointer:
        config["checkpointer"] = _checkpointer

    accumulated_text = ""

    try:
        async for event in _graph.astream_events(
            {"messages": [HumanMessage(content=message)], "session_id": session_id},
            config=config,
            version="v2",
        ):
            kind = event.get("event", "")
            name = event.get("name", "")

            if kind == "on_tool_start":
                tool_input = event.get("data", {}).get("input", "")
                preview = str(tool_input)[:200] if tool_input else ""
                yield ("tool_start", f"🔧 {name}: {preview}")

            elif kind == "on_tool_end":
                output = event.get("data", {}).get("output", "")
                preview = str(output)[:300] if output else ""
                yield ("tool_end", f"✅ {name} → {preview}")

            elif kind == "on_chat_model_stream":
                chunk = event.get("data", {}).get("chunk")
                if chunk and hasattr(chunk, "content") and chunk.content:
                    content = chunk.content if isinstance(chunk.content, str) else str(chunk.content)
                    content = _strip_think(content)
                    if content:
                        accumulated_text += content
                        yield ("text", content)

        # Final response
        final = _strip_think(accumulated_text)
        yield ("done", final)

    except Exception as e:
        yield ("error", str(e))


def chat_streaming(message: str, history: list[dict], session_id: str):
    """Streaming wrapper — yields incremental history updates as tools run."""
    import threading

    result_queue: _queue_mod.Queue = _queue_mod.Queue()
    progress_so_far: list[dict] = []

    original_chat = chat

    async def _run():
        try:
            result = await original_chat(message, session_id)
            result_queue.put(("done", result))
        except Exception as e:
            result_queue.put(("error", str(e)))

    # Run agent in a background thread
    def _thread():
        asyncio.run(_run())

    t = threading.Thread(target=_thread, daemon=True)
    t.start()

    # Poll for progress and yield updates
    placeholder_shown = False
    while t.is_alive():
        try:
            status, data = result_queue.get(timeout=0.5)
            if status == "done":
                for msg in data:
                    meta = msg.get("metadata", {})
                    if meta.get("_clear"):
                        yield [], session_id
                        return
                    if meta.get("_new"):
                        import secrets as _s
                        yield [], _s.token_hex(4)
                        return
                history.extend(data)
                yield history, session_id
                return
            elif status == "error":
                history.append({"role": "assistant", "content": f"**Error:** {data}"})
                yield history, session_id
                return
        except _queue_mod.Empty:
            # Show a working indicator if nothing yet
            if not placeholder_shown:
                history.append({
                    "role": "assistant",
                    "metadata": {"title": "🔬 Working..."},
                    "content": "",
                })
                placeholder_shown = True
                yield history, session_id

    # Thread finished, get final result
    try:
        status, data = result_queue.get_nowait()
        if placeholder_shown:
            history.pop()  # remove working indicator
        if status == "done":
            for msg in data:
                meta = msg.get("metadata", {})
                if meta.get("_clear"):
                    yield [], session_id
                    return
                if meta.get("_new"):
                    import secrets as _s
                    yield [], _s.token_hex(4)
                    return
            history.extend(data)
        elif status == "error":
            history.append({"role": "assistant", "content": f"**Error:** {data}"})
    except _queue_mod.Empty:
        if placeholder_shown:
            history.pop()
        history.append({"role": "assistant", "content": "*Task completed.*"})

    yield history, session_id


# ---------------------------------------------------------------------------
# Settings callbacks
# ---------------------------------------------------------------------------


def _build_settings_callbacks() -> dict:
    def get_tools_list() -> str:
        if _BACKEND == "langgraph" and _graph is not None:
            from tools.lg_tools import get_all_tools
            tools = get_all_tools(_get_store())
            names = sorted(t.name for t in tools)
        elif _agent is not None:
            names = sorted(_agent.tools.tool_names)
        else:
            names = []
        return "\n".join(f"- `{n}`" for n in names) or "No tools registered."

    def get_model_info() -> str:
        if _BACKEND == "langgraph" and _graph_config is not None:
            model = _graph_config.model_name
            return f"**Model:** `{model}`\n\n**Backend:** LangGraph"
        elif _agent is not None:
            model = _agent.model or "unknown"
            effort = getattr(_agent.provider.generation, "reasoning_effort", None) or "default"
            return f"**Model:** `{model}`\n\n**Reasoning:** {effort}"
        return "**Model:** unknown"

    def get_provider_choices() -> list[str]:
        choices = []
        if _config is not None:
            try:
                api_base = _config.get_api_base(_config.agents.defaults.model)
                if api_base:
                    detected = _detect_vllm_model(api_base)
                    label = detected or "local vLLM"
                    choices.append(f"local: {label}")
            except Exception:
                pass
        else:
            # LangGraph backend — check vLLM directly
            detected = _detect_vllm_model("http://host.docker.internal:8000/v1")
            if detected:
                choices.append(f"local: {detected}")
        # Claude models via CLIProxyAPI (OAuth)
        choices.extend([
            "claude: claude-sonnet-4-6",
            "claude: claude-haiku-4-5",
            "claude: claude-opus-4-6",
        ])
        return choices

    def get_current_provider() -> str:
        if _BACKEND == "langgraph" and _graph_config is not None:
            model = _graph_config.model_name
        elif _agent is not None:
            model = (_agent.model or "").replace("openai/", "")
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
        global _graph, _graph_config
        if not choice:
            return "No provider selected."

        parts = choice.split(": ", 1)
        provider_type = parts[0]
        model_name = parts[1] if len(parts) > 1 else ""

        if _BACKEND == "langgraph":
            # Rebuild graph with new model
            if _graph_config is not None:
                if provider_type == "local":
                    _graph_config.model_provider = "vllm"
                    detected = _detect_vllm_model("http://host.docker.internal:8000/v1")
                    _graph_config.model_name = detected or model_name
                elif provider_type == "claude":
                    _graph_config.model_provider = "openai"
                    _graph_config.model_name = model_name
                else:
                    return f"**Error:** Unknown provider: {provider_type}"

                from graph.agent import create_researcher_graph
                _graph = create_researcher_graph(
                    config=_graph_config, knowledge_store=_get_store(),
                    include_subagents=True,
                )
                return f"**Switched to:** `{_graph_config.model_name}` (graph rebuilt)"
            return "**Error:** LangGraph config not initialized."

        # Nanobot backend
        from nanobot.providers.base import GenerationSettings
        from nanobot.providers.litellm_provider import LiteLLMProvider

        if provider_type == "local":
            import litellm
            api_base = _config.get_api_base(_config.agents.defaults.model) if _config else None
            detected = _detect_vllm_model(api_base) if api_base else None
            model = detected or model_name
            if api_base:
                litellm.api_base = api_base

            p = _config.get_provider(_config.agents.defaults.model) if _config else None
            provider = LiteLLMProvider(
                api_key=p.api_key if p else None,
                api_base=api_base,
                default_model=model,
                extra_headers=p.extra_headers if p else None,
                provider_name="vllm",
            )
        elif provider_type == "claude":
            provider = LiteLLMProvider(
                api_key=os.environ.get("OPENAI_API_KEY", ""),
                api_base="http://gateway:4000/v1",
                default_model=f"openai/{model_name}",
                provider_name="openai",
            )
        else:
            return f"**Error:** Unknown provider type: {provider_type}"

        old_gen = _agent.provider.generation
        provider.generation = GenerationSettings(
            temperature=old_gen.temperature,
            max_tokens=old_gen.max_tokens,
            reasoning_effort=old_gen.reasoning_effort,
        )

        _agent.provider = provider
        _agent.model = provider.default_model
        return f"**Switched to:** `{provider.default_model}`"

    def get_subtitle() -> str:
        if _BACKEND == "langgraph" and _graph_config is not None:
            display_model = _graph_config.model_name
        elif _agent is not None:
            display_model = (_agent.model or "").replace("openai/", "")
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
        config_path = Path(__file__).parent / "config" / "security-config.json"
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
    args = parser.parse_args()

    # Initialize observability (shared by both backends)
    import tracing
    import metrics
    tracing.init()
    metrics.init()

    print(f"[researcher] Agent backend: {_BACKEND}")

    if _BACKEND == "langgraph":
        _init_langgraph_agent()
    else:
        # Nanobot backend (legacy)
        _init_agent(args.config)
        _install_audit_wrapper()

        from tools.cve_search import CVESearchTool
        from tools.security_feeds import SecurityFeedsTool
        from tools.github_trending import GitHubTrendingTool
        from tools.security_memory import SecurityMemoryTool
        from tools.browser import BrowserTool
        from tools.discord_feed import DiscordFeedTool
        _agent.tools.register(CVESearchTool())
        _agent.tools.register(SecurityFeedsTool())
        _agent.tools.register(GitHubTrendingTool())
        _agent.tools.register(SecurityMemoryTool(_get_store()))
        _agent.tools.register(BrowserTool())

        if os.environ.get("RABBIT_HOLE_URL"):
            from tools.rabbit_hole_bridge import RabbitHoleBridgeTool
            _agent.tools.register(RabbitHoleBridgeTool())
            print("[researcher] Rabbit Hole bridge registered")
        else:
            print("[researcher] Rabbit Hole bridge: skipped (no RABBIT_HOLE_URL)")

        if os.environ.get("DISCORD_BOT_TOKEN"):
            _agent.tools.register(DiscordFeedTool())
            print("[researcher] Discord feed tool registered")
        else:
            print("[researcher] Discord feed: skipped (no DISCORD_BOT_TOKEN)")

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

    static_dir = Path(__file__).parent / "static"

    fastapi_app = FastAPI(title="protoPen — protoLabs")

    # Chat API endpoint (for evals and programmatic access)
    from pydantic import BaseModel as PydanticBaseModel

    class ChatRequest(PydanticBaseModel):
        message: str
        session_id: str = "api-default"

    @fastapi_app.post("/api/chat")
    async def _api_chat(req: ChatRequest):
        result = await chat(req.message, req.session_id)
        # Extract assistant content
        parts = [m["content"] for m in result if m.get("role") == "assistant" and m.get("content")]
        return {"response": "\n\n".join(parts), "messages": result}

    # OpenAI-compatible chat completions endpoint
    # Allows protoPen to be registered as a model in LiteLLM gateway / OpenWebUI
    import time as _time
    from fastapi.responses import StreamingResponse as _StreamingResponse

    @fastapi_app.post("/v1/chat/completions")
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
                    "choices": [{
                        "index": 0,
                        "delta": {"role": "assistant", "content": content},
                        "finish_reason": None,
                    }],
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
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }

    @fastapi_app.get("/v1/models")
    async def _openai_models():
        return {
            "object": "list",
            "data": [{
                "id": "protopen",
                "object": "model",
                "created": 1774600000,
                "owned_by": "protolabs",
            }],
        }

    # ─── A2A protocol ────────────────────────────────────────────────────────
    # JSON-RPC 2.0 endpoint consumed by protoWorkstacean's A2A plugin.
    # Supports: message/send (synchronous — waits for full response)

    _A2A_API_KEY = os.environ.get("PROTOPEN_API_KEY", os.environ.get("RESEARCHER_API_KEY", ""))

    AGENT_CARD = {
        "name": "protopen",
        "description": (
            "Autonomous pen testing and security intelligence agent. Combines hardware-in-the-loop "
            "security assessments (PortaPack H4M, Flipper Zero, WiFi Marauder, BlackArch) "
            "with threat intelligence capabilities (CVE feeds, security advisories, GitHub, knowledge store). "
            "Runs on a Steam Deck with attached RF/WiFi/RFID peripherals."
        ),
        "url": "http://steamdeck:7870",
        "provider": {"organization": "protoLabsAI"},
        "version": "2.0",
        "capabilities": {"streaming": True, "pushNotifications": False},
        "skills": [
            {
                "id": "passive_recon",
                "name": "Passive Reconnaissance",
                "description": (
                    "Perform passive reconnaissance on a target scope. Includes WiFi AP/station "
                    "enumeration, RF spectrum survey, network host discovery, and service "
                    "fingerprinting. No active probing or transmission — observation only."
                ),
                "inputModes": ["text/plain"],
                "outputModes": ["text/markdown"],
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
                "inputModes": ["text/plain"],
                "outputModes": ["text/markdown"],
            },
            {
                "id": "security_report",
                "name": "Security Report",
                "description": (
                    "Generate a professional security assessment report from engagement "
                    "findings. Triages by severity, correlates across RF/WiFi/network domains, "
                    "identifies attack paths, and provides actionable remediation priorities."
                ),
                "inputModes": ["text/plain"],
                "outputModes": ["text/markdown"],
            },
            {
                "id": "threat_intel",
                "name": "Threat Intelligence",
                "description": (
                    "Research a security topic in depth: searches CVE feeds, security advisories, "
                    "GitHub, web, and internal knowledge store. Returns a structured threat report."
                ),
                "inputModes": ["text/plain"],
                "outputModes": ["text/markdown"],
            },
            {
                "id": "summarize",
                "name": "Summarize",
                "description": (
                    "Summarize recent CVEs, advisories, exploits, or threat intel from the "
                    "knowledge store. Optionally scoped to a topic or time window."
                ),
                "inputModes": ["text/plain"],
                "outputModes": ["text/markdown"],
            },
        ],
    }

    @fastapi_app.get("/.well-known/agent.json", include_in_schema=False)
    async def _agent_card():
        return AGENT_CARD

    from fastapi import Request as _FRequest

    def _extract_a2a_text(params: dict) -> tuple[str, str, dict | None]:
        """Extract text, contextId from A2A params. Returns (text, context_id, error_dict)."""
        message = params.get("message", {})
        context_id = params.get("contextId", "")
        parts = message.get("parts", [])
        text = next((p.get("text", "") for p in parts if p.get("kind") == "text"), "")
        if not text:
            text = next((p.get("text", "") for p in parts), "")
        if not text:
            return "", context_id, {"code": -32600, "message": "No text content in message"}
        return text, context_id, None

    @fastapi_app.post("/a2a", include_in_schema=False)
    async def _a2a(request: _FRequest, req: dict):
        # Optional API key auth
        if _A2A_API_KEY and request.headers.get("x-api-key") != _A2A_API_KEY:
            from fastapi.responses import JSONResponse as _JSONResponse
            return _JSONResponse({"detail": "Unauthorized"}, status_code=401)

        rpc_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params", {})

        # ── message/sendStream → SSE ──────────────────────────────────
        if method == "message/sendStream":
            text, context_id, err = _extract_a2a_text(params)
            if err:
                return {"jsonrpc": "2.0", "id": rpc_id, "error": err}

            import uuid as _uuid
            from starlette.responses import StreamingResponse

            task_id = str(_uuid.uuid4())
            context_id = context_id or f"a2a-{_uuid.uuid4()}"

            async def _sse_generator():
                # Streaming only available with LangGraph backend
                if _BACKEND != "langgraph" or _graph is None:
                    # Fallback: run sync and emit single completed event
                    result_messages = await chat(text, context_id)
                    assistant_parts = [
                        m["content"] for m in result_messages
                        if m.get("role") == "assistant" and m.get("content")
                    ]
                    response_text = "\n\n".join(assistant_parts)
                    evt = json.dumps({
                        "jsonrpc": "2.0", "id": rpc_id,
                        "result": {
                            "id": task_id, "contextId": context_id,
                            "status": {"state": "completed"},
                            "artifacts": [{"parts": [{"kind": "text", "text": response_text}]}],
                        },
                    })
                    yield f"data: {evt}\n\n"
                    return

                # Stream via LangGraph astream_events
                async for event_type, payload in _chat_langgraph_stream(text, context_id):
                    if event_type in ("tool_start", "tool_end"):
                        evt = json.dumps({
                            "jsonrpc": "2.0", "id": rpc_id,
                            "result": {
                                "id": task_id, "contextId": context_id,
                                "status": {
                                    "state": "working",
                                    "message": {"role": "agent", "parts": [{"kind": "text", "text": payload}]},
                                },
                            },
                        })
                        yield f"data: {evt}\n\n"

                    elif event_type == "text":
                        evt = json.dumps({
                            "jsonrpc": "2.0", "id": rpc_id,
                            "result": {
                                "id": task_id, "contextId": context_id,
                                "status": {"state": "working"},
                                "artifacts": [{"parts": [{"kind": "text", "text": payload}], "append": True}],
                            },
                        })
                        yield f"data: {evt}\n\n"

                    elif event_type == "done":
                        evt = json.dumps({
                            "jsonrpc": "2.0", "id": rpc_id,
                            "result": {
                                "id": task_id, "contextId": context_id,
                                "status": {"state": "completed"},
                                "artifacts": [{"parts": [{"kind": "text", "text": payload}]}],
                            },
                        })
                        yield f"data: {evt}\n\n"

                    elif event_type == "error":
                        evt = json.dumps({
                            "jsonrpc": "2.0", "id": rpc_id,
                            "result": {
                                "id": task_id, "contextId": context_id,
                                "status": {"state": "failed", "message": {"role": "agent", "parts": [{"kind": "text", "text": payload}]}},
                            },
                        })
                        yield f"data: {evt}\n\n"

            return StreamingResponse(
                _sse_generator(),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
            )

        # ── message/send → synchronous (existing) ────────────────────
        if method == "message/send":
            text, context_id, err = _extract_a2a_text(params)
            if err:
                return {"jsonrpc": "2.0", "id": rpc_id, "error": err}

            import uuid as _uuid
            task_id = str(_uuid.uuid4())
            context_id = context_id or f"a2a-{_uuid.uuid4()}"

            result_messages = await chat(text, context_id)
            assistant_parts = [
                m["content"] for m in result_messages
                if m.get("role") == "assistant" and m.get("content")
            ]
            response_text = "\n\n".join(assistant_parts)

            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "id": task_id,
                    "contextId": context_id,
                    "status": {"state": "completed"},
                    "artifacts": [{
                        "parts": [{"kind": "text", "text": response_text}]
                    }],
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

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
                    str(sw_path), media_type="application/javascript",
                    headers={"Service-Worker-Allowed": "/"},
                )

        fastapi_app.mount("/static", StaticFiles(directory=str(static_dir)), name="ava-static")

    app = gr.mount_gradio_app(
        fastapi_app, blocks, path="/",
        footer_links=[],
        favicon_path=str(static_dir / "favicon.svg") if (static_dir / "favicon.svg").exists() else None,
    )

    print(f"[protoPen] Starting on http://0.0.0.0:{args.port}")
    uvicorn.run(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    _main()
