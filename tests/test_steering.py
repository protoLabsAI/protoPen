"""Mid-turn steering (protopen-1hw.6): queue, middleware fold-in, endpoints."""

from __future__ import annotations

import asyncio

from fastapi import FastAPI
from fastapi.testclient import TestClient
from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from graph import steering
from graph.middleware.steering import SteeringMiddleware
from graph.state import ResearcherState
from operator_api.routes import register_operator_routes


# ── queue ────────────────────────────────────────────────────────────────────


def test_queue_enqueue_drain_is_fifo_and_clears():
    steering.drain("s")  # ensure clean
    a = steering.enqueue("s", "first")
    steering.enqueue("s", "second")
    assert steering.pending("s") == 2
    items = steering.drain("s")
    assert [i["text"] for i in items] == ["first", "second"]
    assert items[0]["id"] == a
    assert steering.pending("s") == 0  # drained


def test_queue_dequeue_one():
    steering.drain("s")
    a = steering.enqueue("s", "x")
    b = steering.enqueue("s", "y")
    assert steering.dequeue("s", a) is True
    assert [i["id"] for i in steering.pending_items("s")] == [b]
    assert steering.dequeue("s", "nope") is False
    steering.drain("s")


# ── middleware ───────────────────────────────────────────────────────────────


def test_middleware_folds_queued_steer():
    steering.drain("sess")
    steering.enqueue("sess", "actually focus on host 10.0.0.5")
    mw = SteeringMiddleware()
    out = mw.before_model({"messages": [HumanMessage(content="go")], "session_id": "sess"}, None)
    assert out is not None
    assert len(out["messages"]) == 1
    assert "10.0.0.5" in out["messages"][0].content
    assert "while you were working" in out["messages"][0].content  # framing
    assert steering.pending("sess") == 0  # drained


def test_middleware_noop_when_empty_or_no_session():
    assert SteeringMiddleware().before_model({"messages": [], "session_id": "empty"}, None) is None
    assert SteeringMiddleware().before_model({"messages": []}, None) is None  # no session


# ── real-graph fold-in ───────────────────────────────────────────────────────


class _FinalModel(BaseChatModel):
    seen_human: int = 0

    @property
    def _llm_type(self) -> str:
        return "fake-final"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs) -> ChatResult:
        self.seen_human = sum(1 for m in messages if isinstance(m, HumanMessage))
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="ack"))])


def test_steer_folds_into_a_real_graph_turn():
    steering.drain("a2a:live")
    steering.enqueue("a2a:live", "pivot to the DMZ subnet")
    model = _FinalModel()
    agent = create_agent(model=model, tools=[], middleware=[SteeringMiddleware()], state_schema=ResearcherState)
    result = asyncio.run(agent.ainvoke({"messages": [("user", "start")], "session_id": "a2a:live"}))
    # The model saw both the user message and the folded steer message.
    assert model.seen_human == 2
    assert any(isinstance(m, HumanMessage) and "DMZ subnet" in m.content for m in result["messages"])


# ── endpoints ────────────────────────────────────────────────────────────────


def _client():
    app = FastAPI()
    register_operator_routes(
        app, runtime_status=lambda: {}, subagent_list=lambda: [], subagent_run=None, subagent_batch=None
    )
    return TestClient(app)


def test_steer_endpoints_queue_and_cancel():
    steering.drain("epsess")
    c = _client()
    r = c.post("/api/chat/sessions/epsess/steer", json={"text": "look at port 8080"})
    assert r.status_code == 200 and r.json()["ok"] is True and r.json()["pending"] == 1
    mid = r.json()["msg_id"]
    # empty text rejected
    assert c.post("/api/chat/sessions/epsess/steer", json={"text": "  "}).status_code == 400
    # cancel it → queue empties (the blank POST was rejected, never queued)
    d = c.delete(f"/api/chat/sessions/epsess/steer/{mid}")
    assert d.status_code == 200 and d.json()["ok"] is True and d.json()["pending"] == 0
    steering.drain("epsess")
