"""AppState — the process runtime container (ADR 0023, adapted from protoAgent).

Replaces server.py's ambient module-global singletons with one named, injectable
object. Same objects, same lifecycle — server.py reads ``STATE.knowledge_store``
instead of a bare ``_knowledge_store``, and init/reload set ``STATE.x`` instead
of ``global _x``. A single process-wide singleton (``STATE``); ``get_state()`` is
the FastAPI dependency form.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any


@dataclass
class AppState:
    # Compiled graph + its config.
    graph: Any = None
    graph_config: Any = None
    # Conversation checkpointer + prune bookkeeping.
    checkpointer: Any = None
    checkpoint_path: Any = None
    checkpoint_prune_task: Any = None
    # Stores / registries bound into the active graph.
    knowledge_store: Any = None
    skills_index: Any = None
    workflow_registry: Any = None
    # Goal mode / autonomy controller.
    goal_controller: Any = None


STATE = AppState()


def get_state() -> AppState:
    """The process-wide AppState (FastAPI dependency form)."""
    return STATE


# Guards the lazy KnowledgeStore build so concurrent first-callers can't each
# construct one. Boot warms the store single-threaded, so this only matters if a
# request beats init — but get_store() is now a shared helper, so make it safe.
_store_lock = threading.Lock()


def get_store():
    """The process-wide KnowledgeStore, built lazily on first use and cached on
    ``STATE``. Shared by the agent init path and every store-backed command/route
    (ADR 0023: relocated here from server so server.agent_init and server have a
    single, cycle-free source of truth). Double-checked lock so concurrent
    first-callers build exactly one store."""
    if STATE.knowledge_store is None:
        with _store_lock:
            if STATE.knowledge_store is None:
                from knowledge.store import KnowledgeStore

                STATE.knowledge_store = KnowledgeStore()
    return STATE.knowledge_store
