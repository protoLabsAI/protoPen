"""vuln_range: the RANGE_PROXY env must be forwarded to the httpx client (scoped
proxy for range traffic only) and default to a direct connection when unset.

Regression guard for the Steam Deck fix: the Deck runs tailscale in
userspace-networking mode with no kernel route to the tailnet, so range requests
must go through tailscaled's outbound proxy — but ONLY range requests, which is
why the proxy is a per-tool env rather than a global HTTPS_PROXY.
"""

from __future__ import annotations

from tools import vuln_range
from tools.vuln_range import VulnRangeTool


class _FakeResp:
    def raise_for_status(self) -> None:  # noqa: D401
        return None

    def json(self) -> dict:
        return {"exit_code": 0, "stdout": "ok", "stderr": ""}


class _FakeClient:
    last_kwargs: dict = {}

    def __init__(self, **kwargs):
        _FakeClient.last_kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None):
        return _FakeResp()


async def test_range_proxy_forwarded_to_client(monkeypatch):
    monkeypatch.setattr(vuln_range, "_RANGE_PROXY", "http://127.0.0.1:1055")
    monkeypatch.setattr(vuln_range.httpx, "AsyncClient", _FakeClient)

    out = await VulnRangeTool().execute(action="exec", target_image="img:tag", cmd="echo hi")

    assert _FakeClient.last_kwargs.get("proxy") == "http://127.0.0.1:1055"
    assert "[exit 0]" in out


async def test_range_proxy_absent_means_direct(monkeypatch):
    monkeypatch.setattr(vuln_range, "_RANGE_PROXY", None)
    monkeypatch.setattr(vuln_range.httpx, "AsyncClient", _FakeClient)

    await VulnRangeTool().execute(action="exec", target_image="img:tag", cmd="echo hi")

    assert _FakeClient.last_kwargs.get("proxy") is None
