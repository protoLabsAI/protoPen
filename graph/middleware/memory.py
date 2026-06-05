"""MemoryMiddleware — distil durable facts from the conversation (ADR 0021).

After the agent responds, the aux model extracts discrete, durable *facts* from
the last exchange (operator preferences, decisions, stable facts about their
world/projects) and stores them as searchable semantic memory. Runs on a daemon
thread so it never blocks the response; deduped at store time so memory doesn't
accrete duplicates across turns.

"Extract, don't dump": this replaces a prior path that tried to dump the raw
last assistant turn into the store as an "insight" — which both polluted the
store with reasoning/transient text *and* silently no-op'd here (it called a
``add_finding`` method that does not exist on ``KnowledgeStore``).
"""

import threading

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import AIMessage, HumanMessage

# Below this combined-transcript length, the exchange is pleasantries/ack — not
# worth an aux-model call.
_MIN_TRANSCRIPT_CHARS = 40


class MemoryMiddleware(AgentMiddleware):
    """Extract + store durable semantic facts after agent responses."""

    def __init__(self, knowledge_store, config=None):
        super().__init__()
        self._store = knowledge_store
        self._config = config

    def after_agent(self, state, runtime) -> dict | None:
        """Queue the last exchange for async semantic-fact extraction."""
        if self._store is None or not getattr(self._config, "knowledge_facts", True):
            return None

        messages = state.get("messages", [])
        if len(messages) < 2:
            return None

        # The last human + AI exchange is the extraction transcript. Facts
        # accrue incrementally across turns; the store dedups near-duplicates.
        last_human = None
        last_ai = None
        for msg in reversed(messages):
            if isinstance(msg, AIMessage) and last_ai is None:
                last_ai = msg.content if isinstance(msg.content, str) else str(msg.content)
            elif isinstance(msg, HumanMessage) and last_human is None:
                last_human = msg.content if isinstance(msg.content, str) else str(msg.content)
            if last_human and last_ai:
                break

        if not last_human:
            return None

        transcript = f"User: {last_human}\nAssistant: {last_ai or ''}"
        if len(transcript.strip()) < _MIN_TRANSCRIPT_CHARS:
            return None

        store = self._store
        config = self._config

        def _run():
            try:
                from graph.memory_facts import extract_and_store_facts

                extract_and_store_facts(transcript, store=store, config=config)
            except Exception:
                pass

        threading.Thread(target=_run, daemon=True).start()
        return None

    async def aafter_agent(self, state, runtime) -> dict | None:
        return self.after_agent(state, runtime)
