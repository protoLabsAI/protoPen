"""HITL producer: the request_user_input / request_approval tools and the
interactivity gate that keeps headless/autonomous runs from ever parking.

Backend contract (consumed by a2a_executor + the web console):
  - a tool stashes a hitl-v1 payload in graph.hitl_context keyed by session;
  - the chat-stream loop pops it and yields ("input_required", payload);
  - when interactivity is OFF (the default — headless/API), the tools no-op and
    nothing is ever parked.
"""

import pytest

from graph.goals.context import set_current_session
from graph.hitl_context import (
    hitl_allowed,
    set_hitl_allowed,
    take_pending_hitl,
)
from tools.lg_tools import request_approval, request_user_input

SESSION = "test-hitl-session"


def _prime(interactive: bool):
    set_current_session(SESSION)
    set_hitl_allowed(interactive)
    take_pending_hitl(SESSION)  # clear any leftover


@pytest.mark.asyncio
async def test_request_user_input_parks_free_text_question_when_interactive():
    _prime(interactive=True)
    out = await request_user_input.ainvoke({"prompt": "Which subnet should I scan?"})
    assert "Paused" in out
    payload = take_pending_hitl(SESSION)
    assert payload is not None
    assert payload["kind"] == "question"
    assert payload["question"] == "Which subnet should I scan?"


@pytest.mark.asyncio
async def test_request_user_input_builds_flat_form_steps():
    _prime(interactive=True)
    fields = [
        {"id": "env", "label": "Environment", "type": "string", "required": True},
        {"id": "count", "label": "Hosts", "type": "integer"},
    ]
    out = await request_user_input.ainvoke({"prompt": "Confirm params", "fields": fields, "title": "Scan setup"})
    assert "Paused" in out
    payload = take_pending_hitl(SESSION)
    assert payload["kind"] == "form"
    assert payload["title"] == "Scan setup"
    # Flat {id,label,type} steps — protoPen's contract, not JSON-schema.
    assert payload["steps"][0] == {"id": "env", "label": "Environment", "type": "string", "required": True}
    assert payload["steps"][1]["id"] == "count"


@pytest.mark.asyncio
async def test_request_approval_parks_approval_card_when_interactive():
    _prime(interactive=True)
    out = await request_approval.ainvoke({"action": "Escalate to active scan", "detail": "nmap -sS 10.0.0.0/24"})
    assert "Paused" in out
    payload = take_pending_hitl(SESSION)
    assert payload["kind"] == "approval"
    assert payload["title"] == "Escalate to active scan"
    assert payload["detail"] == "nmap -sS 10.0.0.0/24"


@pytest.mark.asyncio
async def test_tools_noop_and_never_park_when_headless():
    # The default / headless case: no operator, autonomy must be preserved.
    _prime(interactive=False)
    assert hitl_allowed() is False

    out1 = await request_user_input.ainvoke({"prompt": "anything?"})
    out2 = await request_approval.ainvoke({"action": "do the thing"})

    assert "do not wait" in out1.lower()
    assert "do not wait" in out2.lower()
    # Nothing was parked — the stream loop would never emit input_required.
    assert take_pending_hitl(SESSION) is None


@pytest.mark.asyncio
async def test_hitl_allowed_defaults_off():
    # A fresh context (no server priming) must default to autonomous.
    take_pending_hitl(SESSION)
    set_hitl_allowed(False)
    assert hitl_allowed() is False
