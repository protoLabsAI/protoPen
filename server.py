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

_graph = None       # LangGraph compiled graph
_graph_config = None  # LangGraphConfig
_checkpointer = None  # LangGraph MemorySaver for session persistence


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
        print("[sitrep] Startup probe injected into system prompt")

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
            raw = report_step.output.strip()
            # Strip markdown code fences the LLM may wrap around JSON
            if raw.startswith("```"):
                raw = re.sub(r"^```(?:json)?\s*\n?", "", raw)
                raw = re.sub(r"\n?```\s*$", "", raw)
            report = json.loads(raw)
            rate_pct = report.get("detection_rate_pct",
                                    report.get("detection_rate", 0) * 100)
            rating = report.get("rating", "UNKNOWN")
            progress_lines.append("\n### ATT&CK Coverage")
            progress_lines.append(
                f"**Rating:** {rating} ({rate_pct:.0f}% detection rate)"
            )
            crit = report.get("critical_findings", [])
            high = report.get("high_findings", [])
            if crit:
                progress_lines.append(
                    f"**Critical gaps:** {len(crit)}"
                )
            if high:
                progress_lines.append(
                    f"**High gaps:** {len(high)}"
                )
            for f in crit[:5]:
                progress_lines.append(
                    f"  - 🔴 {f['technique_id']} {f['technique_name']}"
                )
            for f in high[:5]:
                progress_lines.append(
                    f"  - 🟠 {f['technique_id']} {f['technique_name']}"
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
        # Claude models via CLIProxyAPI (OAuth)
        choices.extend([
            "claude: claude-sonnet-4-6",
            "claude: claude-haiku-4-5",
            "claude: claude-opus-4-6",
        ])
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
                config=_graph_config, knowledge_store=_get_store(),
                include_subagents=True,
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
        "url": "http://steamdeck:7870",
        "provider": {"organization": "protoLabsAI"},
        "version": "2.0",
        "capabilities": {},   # populated by register_a2a_routes()
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

    from a2a_handler import register_a2a_routes
    register_a2a_routes(
        app=fastapi_app,
        chat_stream_fn_factory=_chat_langgraph_stream,
        chat_fn=chat,
        api_key=_A2A_API_KEY,
        agent_card=AGENT_CARD,
    )

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
