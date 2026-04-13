"""Tests for RateLimiter — sliding window rate limiting for tool calls."""
import time
import pytest

from enforcement.rate_limiter import RateLimiter


class TestBasicRateLimiting:
    def test_allows_under_limit(self):
        rl = RateLimiter({"deauth": {"max": 5, "window_seconds": 3600}})
        allowed, reason = rl.check("deauth")
        assert allowed is True
        assert reason is None

    def test_blocks_at_limit(self):
        rl = RateLimiter({"deauth": {"max": 2, "window_seconds": 3600}})
        rl.check("deauth")
        rl.check("deauth")
        allowed, reason = rl.check("deauth")
        assert allowed is False
        assert "deauth" in reason
        assert "2" in reason

    def test_unlisted_action_always_allowed(self):
        rl = RateLimiter({"deauth": {"max": 1, "window_seconds": 3600}})
        allowed, reason = rl.check("nmap_scan")
        assert allowed is True

    def test_empty_limits_allows_all(self):
        rl = RateLimiter({})
        allowed, reason = rl.check("anything")
        assert allowed is True


class TestSlidingWindow:
    def test_window_expiry(self):
        rl = RateLimiter({"test_action": {"max": 1, "window_seconds": 0.1}})
        rl.check("test_action")
        allowed, _ = rl.check("test_action")
        assert allowed is False
        time.sleep(0.15)
        allowed, _ = rl.check("test_action")
        assert allowed is True

    def test_sliding_window_partial_expiry(self):
        rl = RateLimiter({"action": {"max": 2, "window_seconds": 0.2}})
        rl.check("action")  # t=0
        time.sleep(0.12)
        rl.check("action")  # t=0.12
        allowed, _ = rl.check("action")
        assert allowed is False
        time.sleep(0.12)
        allowed, _ = rl.check("action")
        assert allowed is True


class TestMultipleActions:
    def test_independent_counters(self):
        rl = RateLimiter({
            "action_a": {"max": 1, "window_seconds": 3600},
            "action_b": {"max": 1, "window_seconds": 3600},
        })
        rl.check("action_a")
        allowed, _ = rl.check("action_b")
        assert allowed is True

    def test_different_limits(self):
        rl = RateLimiter({
            "fast": {"max": 10, "window_seconds": 3600},
            "slow": {"max": 1, "window_seconds": 3600},
        })
        for _ in range(10):
            rl.check("fast")
        allowed_fast, _ = rl.check("fast")
        assert allowed_fast is False
        allowed_slow, _ = rl.check("slow")
        assert allowed_slow is True


class TestReset:
    def test_reset_clears_counts(self):
        rl = RateLimiter({"action": {"max": 1, "window_seconds": 3600}})
        rl.check("action")
        allowed, _ = rl.check("action")
        assert allowed is False
        rl.reset()
        allowed, _ = rl.check("action")
        assert allowed is True

    def test_reset_single_action(self):
        rl = RateLimiter({
            "a": {"max": 1, "window_seconds": 3600},
            "b": {"max": 1, "window_seconds": 3600},
        })
        rl.check("a")
        rl.check("b")
        rl.reset("a")
        allowed_a, _ = rl.check("a")
        allowed_b, _ = rl.check("b")
        assert allowed_a is True
        assert allowed_b is False
