"""Mid-turn steering queue (ADR — protoAgent v0.43; protopen-1hw.6).

While a turn is streaming, the operator can POST a message that's queued here and
folded into the running turn at the next model call by ``SteeringMiddleware`` —
instead of waiting for the turn to finish or hard-interrupting it. This is the
"steer" half of protoPen's steer/approve companion loop.

A process-wide, thread-safe queue keyed by session id. The HTTP endpoint
``enqueue``s; the middleware ``drain``s at ``before_model``. A still-pending steer
can be ``dequeue``d (the console's ✕). Messages not drained during the turn stay
queued and are picked up on the next ``before_model`` (next turn) — never lost.
"""

from __future__ import annotations

import threading
import uuid

_LOCK = threading.Lock()
_QUEUES: dict[str, list[dict]] = {}


def enqueue(session_id: str, text: str, msg_id: str | None = None) -> str:
    """Queue a steer message for ``session_id``; returns its id."""
    mid = msg_id or f"steer-{uuid.uuid4().hex[:8]}"
    with _LOCK:
        _QUEUES.setdefault(session_id, []).append({"id": mid, "text": text})
    return mid


def drain(session_id: str) -> list[dict]:
    """Remove and return all queued steer items for ``session_id`` (oldest first)."""
    with _LOCK:
        return _QUEUES.pop(session_id, [])


def dequeue(session_id: str, msg_id: str) -> bool:
    """Remove a single still-pending steer by id. Returns True if it was found."""
    with _LOCK:
        q = _QUEUES.get(session_id, [])
        for i, it in enumerate(q):
            if it["id"] == msg_id:
                del q[i]
                if not q:
                    _QUEUES.pop(session_id, None)
                return True
    return False


def pending_items(session_id: str) -> list[dict]:
    with _LOCK:
        return list(_QUEUES.get(session_id, []))


def pending(session_id: str) -> int:
    with _LOCK:
        return len(_QUEUES.get(session_id, []))
