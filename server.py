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

# ---------------------------------------------------------------------------
# Agent setup
# ---------------------------------------------------------------------------

_graph = None  # LangGraph compiled graph
_graph_config = None  # LangGraphConfig
_checkpointer = None  # session checkpointer (durable sqlite or in-memory)
_checkpoint_path = None  # resolved sqlite path when persistent (for the pruner)
_checkpoint_prune_task = None  # background prune-loop handle


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
    global _checkpoint_path
    try:
        from graph.checkpointer import build_sqlite_checkpointer

        path = _resolve_checkpoint_db(configured_db)
        saver = build_sqlite_checkpointer(path)
        _checkpoint_path = path  # the pruner sweeps this file
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
        cfg = _graph_config
        path = _checkpoint_path
        interval_h = getattr(cfg, "checkpoint_prune_interval_hours", 0) if cfg else 0
        if path and cfg and interval_h > 0:
            try:
                max_age = cfg.checkpoint_max_age_days * 86400 if cfg.checkpoint_max_age_days else None
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
        print(f"[sessions] Persistent checkpointer: {path}")
        return saver
    except Exception as exc:
        from langgraph.checkpoint.memory import MemorySaver

        print(f"[sessions] SQLite checkpointer init failed ({exc}); using in-memory (history won't persist)")
        return MemorySaver()


def _init_langgraph_agent():
    """Initialize the LangGraph agent backend."""
    global _graph, _graph_config, _checkpointer

    from graph.agent import create_researcher_graph
    from graph.config import LangGraphConfig
    from sitrep import run_sitrep

    config_path = Path(__file__).parent / "config" / "langgraph-config.yaml"
    _graph_config = LangGraphConfig.from_yaml(config_path)

    store = _get_store()

    # Persistent session checkpointer — bound into the graph at COMPILE time
    # below. A checkpointer set only in the invoke config is ignored by
    # LangGraph, which gave the chat amnesia (every turn started fresh).
    _checkpointer = _build_checkpointer("/sandbox/knowledge/sessions.db")

    # Run startup sitrep — hardware, network, engagement status
    engagement_config = Path(__file__).parent / "config" / "engagement-config.json"
    status_block = run_sitrep(engagement_config)
    if status_block:
        print("[sitrep] Startup probe injected into system prompt")

    _graph = create_researcher_graph(
        config=_graph_config,
        knowledge_store=store,
        include_subagents=True,
        sitrep=status_block,
        checkpointer=_checkpointer,
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
        model = _graph_config.model_name if _graph_config else "unknown"
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


def _strip_think(text: str) -> str:
    text = re.sub(r"<think>[\s\S]*?</think>", "", text)
    text = re.sub(r"</think>\s*", "", text)
    return text.strip()


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

    # Route to LangGraph backend
    return await _chat_langgraph(message, session_id)


async def _chat_langgraph(message: str, session_id: str) -> list[dict[str, Any]]:
    """Process via LangGraph agent backend."""
    import tracing
    from langchain_core.messages import HumanMessage, AIMessage

    tracing.start_trace(session_id=session_id, name="researcher-chat-lg", metadata={"message_preview": message[:100]})
    try:
        # thread_id keys this session's history in the checkpointer (bound at
        # compile time in create_researcher_graph). A checkpointer in the invoke
        # config is ignored by LangGraph, so it is intentionally not set here.
        config = {"configurable": {"thread_id": f"gradio:{session_id}"}, "recursion_limit": 200}

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

    # thread_id keys this session's history in the checkpointer (bound at compile
    # time in create_researcher_graph). The a2a:/gradio: prefixes isolate the two
    # chat paths. A checkpointer in the invoke config is ignored by LangGraph.
    config = {"configurable": {"thread_id": f"a2a:{session_id}"}, "recursion_limit": 200}

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
                history.append(
                    {
                        "role": "assistant",
                        "metadata": {"title": "🔬 Working..."},
                        "content": "",
                    }
                )
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
        from tools.lg_tools import get_all_tools

        tools = get_all_tools(_get_store())
        names = sorted(t.name for t in tools)
        return "\n".join(f"- `{n}`" for n in names) or "No tools registered."

    def get_model_info() -> str:
        if _graph_config is not None:
            model = _graph_config.model_name
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
        if _graph_config is not None:
            model = _graph_config.model_name
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
                config=_graph_config,
                knowledge_store=_get_store(),
                include_subagents=True,
                checkpointer=_checkpointer,
            )
            return f"**Switched to:** `{_graph_config.model_name}` (graph rebuilt)"
        return "**Error:** LangGraph config not initialized."

    def get_subtitle() -> str:
        if _graph_config is not None:
            display_model = _graph_config.model_name
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

    static_dir = Path(__file__).parent / "static"

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

    # ─── A2A protocol ────────────────────────────────────────────────────────
    # All A2A route logic lives in a2a_handler.py.
    # register_a2a_routes() mounts: /a2a (JSON-RPC), /message:send, /message:stream,
    # /tasks/{id}, /tasks/{id}:subscribe, /tasks/{id}:cancel,
    # /tasks/{id}/pushNotificationConfigs, /.well-known/agent.json

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
        },  # streaming + pushNotifications populated by register_a2a_routes()
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

    from a2a_handler import register_a2a_routes

    register_a2a_routes(
        app=fastapi_app,
        chat_stream_fn_factory=_chat_langgraph_stream,
        chat_fn=chat,
        api_key=_A2A_API_KEY,
        agent_card=AGENT_CARD,
    )

    # Alias required by protoWorkstacean agent discovery
    @fastapi_app.get("/.well-known/agent-card.json", include_in_schema=False)
    async def _agent_card_alias():
        return AGENT_CARD

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
            config=_graph_config,
            setup_complete=True,
            graph_loaded=_graph is not None,
            knowledge_store=_knowledge_store,
            scheduler=_scheduler,
        )

    def _operator_subagent_list():
        return _operator_list_subagents(_graph_config)

    async def _operator_subagent_run(req: dict):
        if _graph is None:
            raise RuntimeError("agent graph is not loaded")
        return await _operator_run_manual_subagent(
            config=_graph_config,
            knowledge_store=_knowledge_store,
            scheduler=None,
            description=req.get("description", ""),
            prompt=req.get("prompt", ""),
            subagent_type=req.get("type") or req.get("subagent_type", "researcher"),
            emit_skill=bool(req.get("emit_skill", False)),
        )

    async def _operator_subagent_batch(req: dict):
        if _graph is None:
            raise RuntimeError("agent graph is not loaded")
        return await _operator_run_manual_subagent_batch(
            config=_graph_config,
            knowledge_store=_knowledge_store,
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

    @fastapi_app.on_event("startup")
    async def _start_scheduler():
        try:
            await _scheduler.start()
            print(f"[scheduler] local scheduler started ({_scheduler.path})")
        except Exception as exc:  # noqa: BLE001
            print(f"[scheduler] failed to start: {exc}")

        # Checkpoint pruner — periodic sweep to keep the SQLite history DB bounded.
        global _checkpoint_prune_task
        if _checkpoint_path and _graph_config is not None and _graph_config.checkpoint_prune_interval_hours > 0:
            _checkpoint_prune_task = asyncio.create_task(_checkpoint_prune_loop())

    @fastapi_app.on_event("shutdown")
    async def _stop_scheduler():
        try:
            await _scheduler.stop()
        except Exception as exc:  # noqa: BLE001
            print(f"[scheduler] failed to stop: {exc}")
        if _checkpoint_prune_task is not None:
            _checkpoint_prune_task.cancel()

    # Monitor view: surface the live engagement + findings (protoPen-specific).
    from operator_api.engagement import (
        build_engagement_status as _build_engagement_status,
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

    # Knowledge surface: hybrid search over the threat-intel store.
    from operator_api.knowledge import search_knowledge as _search_knowledge

    def _operator_knowledge_search(query: str, k: int = 10, table: str | None = None):
        return _search_knowledge(_get_store(), query=query, k=k, table=table)

    # Audit surface: recent tool-execution trail.
    from audit import audit_logger as _audit_logger
    from operator_api.audit import recent_audit as _recent_audit

    def _operator_audit_recent(n: int = 50, session_id: str | None = None):
        return _recent_audit(_audit_logger, n=n, session_id=session_id)

    # Live agent monitoring: launch manual subagents as tracked, cancellable
    # background tasks (the synchronous /api/subagents/* path stays available).
    from operator_api.agent_runtime import agent_registry as _agent_registry

    def _operator_agent_launch(req: dict):
        if _graph is None:
            raise RuntimeError("agent graph is not loaded")
        subagent_type = req.get("type") or req.get("subagent_type", "researcher")

        def _factory():
            return _operator_run_manual_subagent(
                config=_graph_config,
                knowledge_store=_knowledge_store,
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
        knowledge_search=_operator_knowledge_search,
        audit_recent=_operator_audit_recent,
        agent_launch=_operator_agent_launch,
        agent_list=lambda: _agent_registry.snapshot(),
        agent_get=lambda task_id: _agent_registry.get(task_id),
        agent_cancel=lambda task_id: _agent_registry.cancel(task_id),
        scheduler_list=_operator_scheduler_list,
        scheduler_add=_operator_scheduler_add,
        scheduler_cancel=_operator_scheduler_cancel,
        chat_commands=_operator_chat_commands,
        api_key=_operator_api_key,
    )

    _web_dist = Path(__file__).parent / "apps" / "web" / "dist"
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
