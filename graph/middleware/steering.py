"""SteeringMiddleware — fold mid-turn steer messages into the run (protopen-1hw.6).

At ``before_model`` it drains the steering queue for the current session and appends
each queued message as a framed ``HumanMessage`` (via the add_messages reducer), so
the model sees it on the next call without the stream being torn down. The frame
tells the agent to fold it in if it changes the task, else acknowledge and continue.
"""

from __future__ import annotations

import logging

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import HumanMessage

from graph import steering
from graph.state import session_id_from_state

log = logging.getLogger(__name__)

_FRAME = (
    "[User message received while you were working — address it now if it changes "
    "the task, otherwise acknowledge briefly and keep going]"
)


class SteeringMiddleware(AgentMiddleware):
    def before_model(self, state, runtime) -> dict | None:
        sid = session_id_from_state(state)
        if not sid:
            return None
        items = steering.drain(sid)
        if not items:
            return None
        msgs = [HumanMessage(content=f"{_FRAME}\n\n{it['text']}") for it in items]
        log.info("[steer] folding %d steer message(s) into session %s", len(msgs), sid)
        return {"messages": msgs}

    async def abefore_model(self, state, runtime) -> dict | None:
        return self.before_model(state, runtime)
