"""
protoPen — AI security intelligence agent powered by local LLMs.

Monitors CVE feeds, security advisories, GitHub for the latest in security threats.
Uses LangGraph as the sole agent runtime.

Usage:
    python -m server                          # default port 7870
    python -m server --config path/to/config  # custom config
"""

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any

from chat_ui import create_chat_app
from runtime.state import STATE, get_store as _get_store  # ADR 0023: the process runtime container
from server.agent_init import _detect_vllm_model, _init_langgraph_agent  # ADR 0023 phase 2b
from server.app import build_app  # ADR 0023 phase 3: FastAPI/Gradio app assembly
from server.chat import chat  # ADR 0023 phase 2b

# Repo root — bundled config / static / workflows / web dist live here. This
# module is now ``server/__init__.py`` (ADR 0023 package promotion), so the root
# is one directory up (``parents[1]``), not ``__file__``'s own dir.
_REPO_ROOT = Path(__file__).resolve().parents[1]


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

    app = build_app(blocks, port=args.port, dump_openapi=args.dump_openapi)
    if app is None:
        # --dump-openapi wrote the spec and asked us to exit before serving
        return

    import uvicorn

    print(f"[protoPen] Starting on http://0.0.0.0:{args.port}")
    uvicorn.run(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    _main()
