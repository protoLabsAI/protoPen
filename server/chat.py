"""Chat backend — the LangGraph turn loop (ADR 0023 phase 2b).

Extracted from server/__init__.py: the Gradio/programmatic ``chat`` entry, the
A2A streaming generator ``_chat_langgraph_stream`` (consumed by
``a2a_executor.ProtoPenExecutor``), and their helpers. Reads STATE; slash
commands dispatch back to ``server._handle_command`` via a lazy import (breaks
the import cycle: server/__init__ imports these entry points from here).
"""

from __future__ import annotations

import asyncio
import json
import queue as _queue_mod
import re
from typing import Any

from runtime.state import STATE


def _strip_think(text: str) -> str:
    text = re.sub(r"<think>[\s\S]*?</think>", "", text)
    text = re.sub(r"</think>\s*", "", text)
    return text.strip()


# ── on-demand slash skills / subagents (protopen-1hw.13 / 1hw.14) ─────────────


def _skill_run_input(args: str) -> str | None:
    """For ``/skill <name> [extra]``, return the turn input that runs the named
    skill's body — including ``user_only`` skills excluded from auto-retrieval
    (protopen-1hw.13). None when there's no skills index or no such skill."""
    idx = STATE.skills_index
    name, _, extra = args.strip().partition(" ")
    if idx is None or not name:
        return None
    rec = idx.get_skill(name)
    if rec is None:
        return None
    head = f"Run the '{rec.name}' skill now. Follow its instructions exactly:\n\n{rec.prompt_template or ''}"
    extra = extra.strip()
    return f"{head}\n\nAdditional context for this run: {extra}" if extra else head


async def _run_dream(session_id: str) -> str:
    """Run the dream memory-consolidation subagent on demand (protopen-1hw.14)."""
    from graph.agent import run_manual_subagent

    if STATE.graph_config is None:
        return "Error: agent not ready."
    try:
        return await run_manual_subagent(
            STATE.graph_config,
            STATE.knowledge_store,
            None,
            description="memory consolidation",
            prompt=(
                "Run a memory consolidation pass: inventory stored facts with memory_list, then "
                "prune stale/superseded/duplicate ones with forget_memory (one id at a time, be "
                "conservative). Report what you reviewed and pruned."
            ),
            subagent_type="dream",
        )
    except Exception as exc:  # noqa: BLE001
        return f"Error: dream pass failed: {exc}"


async def chat(message: str, session_id: str) -> list[dict[str, Any]]:
    """Route to the active backend."""
    from server import _handle_command  # lazy: avoids the chat<->__init__ import cycle

    # /goal control messages (set / status / clear) short-circuit the turn.
    if STATE.goal_controller is not None:
        reply = await STATE.goal_controller.parse_control(message, session_id)
        if reply is not None:
            return [{"role": "assistant", "content": reply}]

    # Slash commands are handled identically by both backends
    stripped = message.strip()
    if stripped.startswith("/"):
        parts = stripped.split(None, 1)
        cmd = parts[0][1:].lower()
        args = parts[1] if len(parts) > 1 else ""
        # /skill <name>: run a skill's body on demand (incl. user_only skills).
        if cmd == "skill":
            skill_input = _skill_run_input(args)
            if skill_input is None:
                target = args.split()[0] if args.strip() else ""
                msg = f"No such skill {target!r}." if target else "Usage: /skill <name>"
                return [{"role": "assistant", "content": msg}]
            return await _chat_langgraph(skill_input, session_id)
        # /dream: run the memory-consolidation subagent.
        if cmd == "dream":
            return [{"role": "assistant", "content": await _run_dream(session_id)}]
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

        # Mark the session for any goal-aware tool (set_goal) running this turn.
        from graph.goals.context import set_current_session

        set_current_session(session_id)

        result = await STATE.graph.ainvoke(
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


# Cap tool input/output previews so a single frame stays small on the wire.
_TOOL_PREVIEW_CHARS = 800


def _coerce_tool_value(value) -> str:
    """Render a tool input/output for a tool-call card.

    Structured values (dict/list) become compact JSON with double quotes so
    the console can pretty-print them — Python's ``str()`` would emit a repr
    with single quotes that no JSON parser accepts. Everything else is
    stringified. Always truncated to keep the SSE frame small.
    """
    if value is None or value == "":
        return ""
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False, default=str)[:_TOOL_PREVIEW_CHARS]
        except (TypeError, ValueError):
            pass
    return str(value)[:_TOOL_PREVIEW_CHARS]


def _coerce_tool_output(value) -> str:
    """Unwrap a tool result to its payload.

    ``on_tool_end`` hands back the LangChain ``ToolMessage``, whose ``str()``
    leaks ``name=``/``tool_call_id=`` noise — the card wants the actual
    ``.content``. Falls back to the raw value for plain returns.
    """
    return _coerce_tool_value(getattr(value, "content", value))


async def _chat_langgraph_stream(
    message: str,
    session_id: str,
    *,
    resume: bool = False,
    caller_trace: dict | None = None,
    interactive: bool = False,
):
    """Async generator that yields (event_type, payload) tuples via astream_events.

    event_type is one of: "status", "tool_start", "tool_end", "text",
    "input_required", "done", "error".
    ``tool_start`` / ``tool_end`` payloads are structured dicts ({id, name,
    input|output}) keyed by the langchain ``run_id`` so the console can pair
    start↔end and render a live per-tool card; the executor also derives a
    text status from them for text-only consumers.

    Called by ``a2a_executor.ProtoPenExecutor``. ``caller_trace`` is the
    ``a2a.trace`` metadata from the inbound A2A message (Langfuse cross-agent
    propagation); when present it's stamped onto this turn's trace. ``resume``
    marks a continuation of an existing task (HITL) — protoPen has no in-stream
    pause, and the checkpointer keys history by ``session_id``, so a resumed
    message continues the same thread without special handling.
    """
    from langchain_core.messages import HumanMessage

    if caller_trace:
        try:
            import tracing as _tracing

            _tracing.set_caller_context(caller_trace)
        except Exception:
            pass

    # /goal control messages (set / status / clear) short-circuit the turn.
    if STATE.goal_controller is not None:
        reply = await STATE.goal_controller.parse_control(message, session_id)
        if reply is not None:
            yield ("text", reply)
            yield ("done", reply)
            return

    # On-demand slash dispatch on the primary (A2A streaming) path. /skill rewrites
    # the turn to run a skill body (incl. user_only); /dream runs the consolidation
    # subagent and short-circuits. Other slashes fall through to the agent.
    _stripped = message.strip()
    if _stripped.startswith("/"):
        _parts = _stripped.split(None, 1)
        _cmd = _parts[0][1:].lower()
        _cargs = _parts[1] if len(_parts) > 1 else ""
        if _cmd == "skill":
            skill_input = _skill_run_input(_cargs)
            if skill_input is None:
                target = _cargs.split()[0] if _cargs.strip() else ""
                err = f"No such skill {target!r}." if target else "Usage: /skill <name>"
                yield ("text", err)
                yield ("done", err)
                return
            message = skill_input  # run the agent with the skill body
        elif _cmd == "dream":
            out = await _run_dream(session_id)
            yield ("text", out)
            yield ("done", out)
            return

    # thread_id keys this session's history in the checkpointer (bound at compile
    # time in create_researcher_graph). The a2a:/gradio: prefixes isolate the two
    # chat paths. A checkpointer in the invoke config is ignored by LangGraph.
    config = {"configurable": {"thread_id": f"a2a:{session_id}"}, "recursion_limit": 200}

    # Mark the session for any goal-aware tool (set_goal) running this turn.
    from graph.goals.context import set_current_session

    set_current_session(session_id)

    # Gate HITL pausing for this turn. Off unless the caller opted in
    # (protolabs.interactive) — a headless/autonomous run never blocks on input,
    # so request_user_input / request_approval no-op instead of parking.
    from graph.hitl_context import set_hitl_allowed, take_pending_hitl

    set_hitl_allowed(interactive)
    take_pending_hitl(session_id)  # clear any stale request from a prior turn

    # Background subagents (ADR 0050): fold the results of any completed
    # background delegations for this session into THIS turn as a
    # <task-notification> the agent reads before the user's message. Drained
    # exactly once (the manager marks them notified). After the /goal
    # short-circuit so a /goal command doesn't consume them.
    from graph.background import get_background_manager, render_task_notifications

    _bg = render_task_notifications(get_background_manager().drain_notifications(session_id))

    # Goal mode: run the turn, then — if an active goal isn't met — re-invoke on
    # the same thread with a continuation prompt until the verifier passes, the
    # iteration budget runs out, or it's flagged unachievable. ``hard_cap`` is an
    # absolute backstop above the goal's own iteration cap.
    turn_input = f"{_bg}\n\n{message}" if _bg else message
    guard = 0
    hard_cap = 30

    try:
        while True:
            accumulated_text = ""
            async for event in STATE.graph.astream_events(
                {"messages": [HumanMessage(content=turn_input)], "session_id": session_id},
                config=config,
                version="v2",
            ):
                kind = event.get("event", "")
                name = event.get("name", "")

                if kind == "on_tool_start":
                    tool_input = event.get("data", {}).get("input", "")
                    yield (
                        "tool_start",
                        {
                            "id": event.get("run_id") or name,
                            "name": name,
                            "input": _coerce_tool_value(tool_input),
                        },
                    )

                elif kind == "on_tool_end":
                    output = event.get("data", {}).get("output", "")
                    yield (
                        "tool_end",
                        {
                            "id": event.get("run_id") or name,
                            "name": name,
                            "output": _coerce_tool_output(output),
                        },
                    )

                elif kind == "on_chat_model_stream":
                    chunk = event.get("data", {}).get("chunk")
                    if chunk and hasattr(chunk, "content") and chunk.content:
                        content = chunk.content if isinstance(chunk.content, str) else str(chunk.content)
                        content = _strip_think(content)
                        if content:
                            accumulated_text += content
                            yield ("text", content)

            final = _strip_think(accumulated_text)

            # HITL pause: a tool (request_user_input / request_approval) asked for
            # the operator this turn — park as input-required ahead of any goal
            # continuation. The console renders the form/approval card and resumes
            # with a follow-up message on this session. Only reachable when the
            # caller opted into interactivity (otherwise the tools never set this).
            pending = take_pending_hitl(session_id)
            if pending is not None:
                yield ("input_required", pending)
                return

            # No active goal → this is a normal turn; finish.
            if STATE.goal_controller is None or STATE.goal_controller.active_goal(session_id) is None:
                yield ("done", final)
                return

            guard += 1
            decision = await STATE.goal_controller.evaluate(session_id, last_text=final)
            if decision is None or decision.action == "done" or guard >= hard_cap:
                if decision is not None and decision.note:
                    yield ("text", f"\n\n_{decision.note}_")
                yield ("done", final)
                return

            # Goal not met — re-invoke with the continuation prompt.
            yield ("status", decision.note)
            turn_input = decision.message

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
