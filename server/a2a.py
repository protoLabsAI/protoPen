"""A2A surface wiring (ADR 0023 phase 2b).

Extracted from server/__init__.py: the proto AgentCard builder and the a2a-sdk
mount (durable stores, the ProtoPenExecutor bridge, X-API-Key auth, JSON-RPC +
agent-card routes). `mount_a2a` is param-driven — build_app passes the card
dict, api key, terminal hook, and the chat-stream generator — so this module
needs nothing from server/__init__.
"""

from __future__ import annotations

import asyncio
import os


def _build_agent_card_proto(card_data: dict, *, bearer: bool = False):
    """Build the A2A 1.0 ``AgentCard`` (proto) served at
    ``/.well-known/agent-card.json``, applying the protoLabs fleet conventions
    via ``protolabs_a2a.build_agent_card``.

    ``card_data`` is the plain dict (name / description / url / version / skills)
    — protoPen passes the ``card_dict`` defined in ``build_app``. protoPen's
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


def mount_a2a(fastapi_app, *, api_key, card_dict, terminal_hook, chat_stream) -> None:
    """Wire the a2a-sdk surface onto the FastAPI app. Extracted from build_app."""
    import httpx

    from a2a.server.request_handlers import DefaultRequestHandler
    from a2a.server.routes.agent_card_routes import create_agent_card_routes
    from a2a.server.routes.fastapi_routes import add_a2a_routes_to_fastapi
    from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes

    import a2a_auth
    from a2a_executor import ProtoPenExecutor, set_terminal_hook
    from a2a_stores import build_a2a_stores, build_push_sender, initialize_a2a_stores

    set_terminal_hook(terminal_hook)  # ADR 0003: surface Activity turns

    # Request-time auth + origin enforcement (a2a-sdk advertises schemes on the
    # card but does not enforce them). protoPen uses X-API-Key only
    # (PROTOPEN_API_KEY / RESEARCHER_API_KEY); origin via A2A_ALLOWED_ORIGINS.
    a2a_auth.install(
        fastapi_app,
        bearer_token="",
        api_key=api_key,
        allowed_origins_raw=os.environ.get("A2A_ALLOWED_ORIGINS", ""),
    )

    a2a_card = _build_agent_card_proto(card_dict)

    # Durable SQLite-backed task + push-config stores (survive restart; 24h TTL
    # sweep on tasks). The push-config store rejects SSRF callback URLs at
    # set-time; the matching push sender re-validates at send-time.
    task_store, push_config_store, task_db, push_db = build_a2a_stores()
    asyncio.run(initialize_a2a_stores(task_store, push_config_store))
    print(f"[a2a] durable stores ready (tasks={task_db}, push={push_db})")

    push_client = httpx.AsyncClient(timeout=30)
    a2a_request_handler = DefaultRequestHandler(
        agent_executor=ProtoPenExecutor(chat_stream),
        task_store=task_store,
        agent_card=a2a_card,
        push_config_store=push_config_store,
        push_sender=build_push_sender(push_config_store, push_client),
    )
    add_a2a_routes_to_fastapi(
        fastapi_app,
        agent_card_routes=create_agent_card_routes(a2a_card),
        jsonrpc_routes=create_jsonrpc_routes(a2a_request_handler, rpc_url="/a2a"),
    )
    print("[a2a] a2a-sdk routes mounted (JSON-RPC at /a2a, card at /.well-known/agent-card.json)")
