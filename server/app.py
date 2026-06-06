"""protoPen ASGI app assembly (ADR 0023 phase 3).

``build_app`` assembles the full FastAPI REST surface — chat (``/api/chat``,
``/v1/*``), the A2A 1.0 surface, the operator console API, Prometheus ``/metrics``,
PWA static — and mounts the Gradio console at ``/``. Split out of
``server.__init__._main`` so the app is constructible (and OpenAPI-dumpable)
without the CLI/serve wrapper. Verbatim move from _main; zero functional change.

Returns the mounted ASGI app ready for uvicorn, or ``None`` when ``dump_openapi``
wrote the spec and the caller should exit before serving.

NB: no ``from __future__ import annotations`` here — the inline ``ChatRequest``
Pydantic model is built in build_app's local scope, and PEP 563 stringized
annotations leave it not-fully-defined when FastAPI generates the OpenAPI schema.
"""

import asyncio
import json
import os
from pathlib import Path

from events import ACTIVITY_CONTEXT, EventBus
from events.sse import sse_event_stream
from runtime.state import STATE, get_store as _get_store
from server.agent_init import _checkpoint_prune_loop
from server.chat import chat, _chat_langgraph_stream, _strip_think

# Repo root — bundled static / web dist live here (server/app.py is one dir down).
_REPO_ROOT = Path(__file__).resolve().parents[1]

# Server→client SSE push channel (ADR 0003). Process-lifetime singleton:
# producers (A2A terminal hook, scheduler, inbox) publish; /api/events streams
# to connected consoles. Read-only — consoles never push back through it.
_event_bus = EventBus()


def build_app(blocks, *, port: int, dump_openapi: str | None = None):
    """Assemble the protoPen ASGI app (see module docstring)."""
    # ---------------------------------------------------------------------------
    # FastAPI + PWA static serving
    # ---------------------------------------------------------------------------
    import gradio as gr
    import metrics
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
            return None
        text = _strip_think(getattr(outcome, "text", "") or "")
        if not text.strip():
            return None
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

    # a2a-sdk surface (durable stores, ProtoPenExecutor bridge, X-API-Key auth,
    # JSON-RPC + agent-card routes) — wiring extracted to server/a2a.py (ADR 0023).
    from server.a2a import mount_a2a

    mount_a2a(
        fastapi_app,
        api_key=_A2A_API_KEY,
        card_dict=AGENT_CARD,
        terminal_hook=_a2a_terminal,
        chat_stream=_chat_langgraph_stream,
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
        invoke_url=f"http://127.0.0.1:{port}",
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

    # Capabilities catalog (protopen-1vd): browseable, categorized view of the
    # agent's callable tools — what protoPen can DO. Read-only over the registry.
    def _operator_tools_list():
        from operator_api.capabilities import list_capabilities

        return list_capabilities(_get_store())

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
        from server import _CHAT_COMMANDS  # command-table source of truth lives in the package root

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
        tools_list=_operator_tools_list,
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
    if dump_openapi:
        spec = fastapi_app.openapi()
        out = Path(dump_openapi)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n")
        print(f"[protoPen] Wrote OpenAPI spec to {out} ({len(spec.get('paths', {}))} paths)")
        return None

    app = gr.mount_gradio_app(
        fastapi_app,
        blocks,
        path="/",
        footer_links=[],
        favicon_path=str(static_dir / "favicon.svg") if (static_dir / "favicon.svg").exists() else None,
    )

    return app
