"""Sliding-window rate limiter for tool call frequency enforcement.

In-memory only — resets on process restart (by design: rate limits are
per-engagement, not persistent). For persistent audit, use EngagementStore.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Optional


class RateLimiter:
    """Sliding-window rate limiter for pentest tool calls.

    Args:
        limits: Dict mapping action names to limit configs.
                Example: {"deauth": {"max": 10, "window_seconds": 3600}}
                Actions not in this dict are unlimited.
    """

    def __init__(self, limits: dict):
        self._limits = limits
        self._windows: dict[str, list[float]] = defaultdict(list)

    def check(self, action: str) -> tuple[bool, Optional[str]]:
        """Check if an action is within its rate limit.

        Returns:
            (True, None) if allowed.
            (False, reason_string) if rate-limited.
        """
        limit_cfg = self._limits.get(action)
        if limit_cfg is None:
            return True, None

        max_calls = limit_cfg["max"]
        window_secs = limit_cfg["window_seconds"]
        now = time.monotonic()

        cutoff = now - window_secs
        timestamps = self._windows[action]
        self._windows[action] = [t for t in timestamps if t > cutoff]

        if len(self._windows[action]) >= max_calls:
            return False, (f"Rate limit exceeded for '{action}': {max_calls} calls per {window_secs}s window")

        self._windows[action].append(now)
        return True, None

    def reset(self, action: Optional[str] = None):
        """Reset rate limit counters.

        Args:
            action: If provided, reset only that action. Otherwise reset all.
        """
        if action:
            self._windows.pop(action, None)
        else:
            self._windows.clear()
