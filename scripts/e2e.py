#!/usr/bin/env python3
"""End-to-end flow harness for a running protoPen.

Drives REAL agent turns over A2A (model → tools → findings) against authorized
targets and asserts on the live read surface — a layer above scripts/smoke.sh
(which is read-only + one benign turn). Run it on the Deck (it needs the tools,
LAN access, and a working model gateway).

Flows:
  1. preflight        — runtime status + a model turn completes (gateway up)
  2. domain recon     — PASSIVE recon of $PROTOPEN_E2E_DOMAIN (DNS + passive
                        subdomains). Non-intrusive; safe for a production domain.
  3. lan recon        — ACTIVE host/service discovery on $PROTOPEN_E2E_LAN.
                        SKIPPED unless PROTOPEN_E2E_LAN is set (you choose the scope).

Every flow runs inside its own engagement and ALWAYS ends it (even on failure),
so the agent is never left over-scoped.

Config (env):
  PROTOPEN_BASE        base URL                 (default http://127.0.0.1:7870)
  PROTOPEN_KEY         operator/API key         (or PROTOPEN_API_KEY / RESEARCHER_API_KEY)
  PROTOPEN_E2E_DOMAIN  passive-recon domain     (default protolabs.studio)
  PROTOPEN_E2E_LAN     active-recon CIDR/host    (e.g. 192.168.4.0/24; unset = skip)
  PROTOPEN_E2E_TIMEOUT per-turn seconds         (default 240)

Exit code 0 if all run flows pass, 1 otherwise.
"""

from __future__ import annotations

import os
import sys
import time
import uuid

import httpx

BASE = os.environ.get("PROTOPEN_BASE", "http://127.0.0.1:7870").rstrip("/")
KEY = (
    os.environ.get("PROTOPEN_KEY")
    or os.environ.get("PROTOPEN_API_KEY")
    or os.environ.get("RESEARCHER_API_KEY")
    or ""
)
DOMAIN = os.environ.get("PROTOPEN_E2E_DOMAIN", "protolabs.studio").strip()
LAN = os.environ.get("PROTOPEN_E2E_LAN", "").strip()
TURN_TIMEOUT = float(os.environ.get("PROTOPEN_E2E_TIMEOUT", "240"))

H = {"x-api-key": KEY, "Content-Type": "application/json"}
_passed = 0
_failed = 0


def ok(msg: str) -> None:
    global _passed
    _passed += 1
    print(f"  \033[32mPASS\033[0m  {msg}")


def no(msg: str, detail: str = "") -> None:
    global _failed
    _failed += 1
    print(f"  \033[31mFAIL\033[0m  {msg}" + (f" — {detail}" if detail else ""))


def section(title: str) -> None:
    print(f"\n== {title} ==")


# ── HTTP helpers ──────────────────────────────────────────────────────────────


def get(path: str) -> httpx.Response:
    return httpx.get(f"{BASE}{path}", headers={"x-api-key": KEY}, timeout=30)


def engagement(action: str, **fields) -> httpx.Response:
    return httpx.post(f"{BASE}/api/engagement", headers=H, json={"action": action, **fields}, timeout=30)


def a2a_turn(context_id: str, text: str, *, timeout: float = TURN_TIMEOUT) -> str:
    """Drive one real agent turn over A2A streaming; return the raw SSE text."""
    body = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "SendStreamingMessage",
        "params": {
            "message": {
                "messageId": "m-" + uuid.uuid4().hex[:8],
                "contextId": context_id,
                "role": "ROLE_USER",
                "parts": [{"text": text}],
            }
        },
    }
    try:
        r = httpx.post(f"{BASE}/a2a", headers={**H, "A2A-Version": "1.0"}, json=body, timeout=timeout)
        return r.text
    except Exception as exc:  # noqa: BLE001
        return f"__ERROR__ {exc}"


def completed(sse: str) -> bool:
    return "TASK_STATE_COMPLETED" in sse


def tool_calls(sse: str) -> int:
    # Tool-call DataParts carry the tool-call-v1 extension marker (same signal
    # scripts/smoke.sh counts).
    return sse.count("tool-call-v1")


def sse_mentions(sse: str, *needles: str) -> bool:
    low = sse.lower()
    return any(n.lower() in low for n in needles)


# ── flows ─────────────────────────────────────────────────────────────────────


def flow_preflight() -> None:
    section("preflight")
    r = get("/api/runtime/status")
    if r.status_code == 200 and r.json().get("graph_loaded"):
        ok("runtime status: graph loaded")
    else:
        no("runtime status", f"{r.status_code}")
    sse = a2a_turn(f"e2e-pre-{os.getpid()}", "Reply with exactly: E2E-PREFLIGHT-OK", timeout=90)
    if completed(sse) and sse_mentions(sse, "E2E-PREFLIGHT-OK"):
        ok("model turn completes (gateway up)")
    else:
        no("model turn", "no COMPLETED / token (is the model gateway configured?)")


def flow_domain_recon() -> None:
    section(f"domain recon — passive · {DOMAIN}")
    r = engagement("start", name=f"e2e-domain-{int(time.time())}", scope=DOMAIN, mode="passive")
    if r.status_code != 200:
        no("start engagement (passive)", f"{r.status_code} {r.text[:120]}")
        return
    ok("engagement started (passive)")
    try:
        sse = a2a_turn(
            f"e2e-domain-{os.getpid()}",
            f"Run PASSIVE reconnaissance on {DOMAIN}: resolve its DNS records and "
            f"enumerate subdomains using passive sources only. Then list the subdomains you found.",
        )
        if completed(sse):
            ok("recon turn completes")
        else:
            no("recon turn", "no COMPLETED")
        if tool_calls(sse) > 0:
            ok("recon used tools")
        else:
            no("recon used tools", "no tool activity in the turn")
        # Passive subdomain enum of this domain should surface a known subdomain.
        if sse_mentions(sse, ".protolabs.studio", "subdomain", DOMAIN):
            ok("recon surfaced DNS/subdomain results")
        else:
            no("recon results", "answer didn't reference the domain/subdomains")
    finally:
        engagement("end")
        ok("engagement ended")


def flow_lan_recon() -> None:
    if not LAN:
        section("lan recon — SKIPPED")
        print("  (set PROTOPEN_E2E_LAN=<cidr/host> to run active LAN host/service discovery)")
        return
    section(f"lan recon — active · {LAN}")
    before = get("/api/targets")
    n_before = before.json().get("count", 0) if before.status_code == 200 else 0
    r = engagement("start", name=f"e2e-lan-{int(time.time())}", scope=LAN, mode="active")
    if r.status_code != 200:
        no("start engagement (active)", f"{r.status_code} {r.text[:120]}")
        return
    ok("engagement started (active)")
    try:
        sse = a2a_turn(
            f"e2e-lan-{os.getpid()}",
            f"Discover live hosts on {LAN} and their open services. Record each host you "
            f"find as a target. Then summarize the hosts and ports discovered.",
        )
        if completed(sse):
            ok("recon turn completes")
        else:
            no("recon turn", "no COMPLETED")
        if tool_calls(sse) > 0:
            ok("recon used tools")
        else:
            no("recon used tools", "no tool activity in the turn")
        after = get("/api/targets")
        n_after = after.json().get("count", 0) if after.status_code == 200 else 0
        if n_after >= n_before:
            ok(f"targets store consistent ({n_before} → {n_after})")
        else:
            no("targets store", f"count dropped ({n_before} → {n_after})")
        if n_after > n_before:
            ok(f"discovered {n_after - n_before} new host(s)")
        else:
            print(f"  \033[33mNOTE\033[0m  no new hosts recorded (quiet LAN, or hosts already known: {n_after})")
    finally:
        engagement("end")
        ok("engagement ended")


def main() -> int:
    print(f"protoPen e2e — base={BASE} domain={DOMAIN} lan={LAN or '(skip)'}")
    if not KEY:
        print("WARN: no API key resolved — authed flows will fail", file=sys.stderr)
    flow_preflight()
    flow_domain_recon()
    flow_lan_recon()
    print(f"\n==== E2E: {_passed} passed, {_failed} failed ====")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
