"""graph/sdk.py host-free primitives (protopen-1hw.5): telemetry, Knobs, Supervisor."""

from __future__ import annotations

import asyncio

from graph.sdk import (
    DecisionLog,
    Knobs,
    Supervisor,
    make_knob_tools,
    render_html,
    supervise,
    telemetry,
)


async def _poll(cond, timeout=2.0, step=0.02):
    waited = 0.0
    while waited < timeout:
        if cond():
            return True
        await asyncio.sleep(step)
        waited += step
    return cond()


# ── DecisionLog + telemetry + render_html ────────────────────────────────────


def test_decision_log_cap_and_entries():
    log = DecisionLog(cap=3)
    for i in range(5):
        log.record("tune", f"step {i}", reason="x")
    assert len(log) == 3
    assert [e["detail"] for e in log.entries()] == ["step 2", "step 3", "step 4"]
    assert log.entries(1)[0]["reason"] == "x"
    log.clear()
    assert len(log) == 0


def test_telemetry_envelope_accepts_decisionlog():
    log = DecisionLog()
    log.record("strategy", "→ passive")
    env = telemetry(status="ok", metrics={"hosts": 3}, hints=["h"], decisions=log, extra_key="v")
    assert env["status"] == "ok"
    assert env["metrics"] == {"hosts": 3}
    assert env["hints"] == ["h"]
    assert env["decisions"][0]["action"] == "strategy"
    assert env["extra_key"] == "v"


def test_render_html_is_self_contained_and_escaped():
    env = telemetry(
        status="running <b>",
        metrics={"hosts": 1200},
        decisions=[{"action": "tune", "detail": "a→b"}],
        sections=[{"title": "Hosts", "columns": ["ip", "os"], "rows": [["10.0.0.1", "linux"]]}],
        hints=["<script>x</script>"],
    )
    html = render_html(env, title="Recon")
    assert html.startswith("<style>") and "pl-tele" in html
    assert "&lt;b&gt;" in html  # status escaped
    assert "1,200" in html  # int formatted
    assert "&lt;script&gt;" in html  # hint escaped
    assert "Hosts" in html and "10.0.0.1" in html


# ── Knobs ────────────────────────────────────────────────────────────────────


def test_knobs_define_set_clamp_choices():
    k = (
        Knobs()
        .define("aggression", 2, lo=0, hi=5, help="loudness")
        .define("posture", "stealth", choices=["stealth", "loud"])
    )
    assert k.get("aggression") == 2
    k.set("aggression", "9")  # clamps to hi
    assert k.get("aggression") == 5
    k.set("aggression", "-3")  # clamps to lo
    assert k.get("aggression") == 0
    assert "must be one of" in k.set("posture", "nope")  # invalid choice → message
    k.set("posture", "LOUD")  # case-insensitive choice
    assert k.get("posture") == "loud"
    assert "unknown knob" in k.set("nope", "1")
    assert len(k.changes()) >= 2  # tunes logged


def test_knobs_presets_are_not_cumulative():
    k = Knobs().define("a", 1).define("b", 1)
    k.preset("p1", {"a": 10}).preset("p2", {"b": 20})
    k.apply_preset("p1")
    assert (k.get("a"), k.get("b")) == (10, 1)
    k.apply_preset("p2")  # resets to defaults first, then applies
    assert (k.get("a"), k.get("b")) == (1, 20)
    assert "unknown preset" in k.apply_preset("nope")


def test_make_knob_tools_generates_prefixed_tools():
    k = Knobs().define("a", 1).preset("p", {"a": 2})
    tools = make_knob_tools(k, prefix="recon")
    names = {t.name for t in tools}
    assert names == {"recon_knobs", "recon_tune", "recon_preset"}


# ── Supervisor ───────────────────────────────────────────────────────────────


def test_supervisor_oneshot_completes():
    async def scenario():
        ran = {"n": 0}

        async def work():
            ran["n"] += 1
            return "done"

        sup = supervise(work, name="t", loop=False, interval=0.05)
        sup.start()
        await _poll(lambda: not sup.running() and sup.status()["result"] == "done")
        st = sup.status()
        await sup.aclose()
        return ran["n"], st

    n, st = asyncio.run(scenario())
    assert n == 1 and st["result"] == "done"


def test_supervisor_rekicks_after_crash_with_recovery():
    async def scenario():
        calls = {"n": 0}

        async def work():
            calls["n"] += 1
            if calls["n"] < 2:
                raise RuntimeError("boom")
            return "ok"

        sup = supervise(work, name="t", loop=True, breath=0.01, interval=0.05, on_crash=lambda r: True)
        sup.start()
        await _poll(lambda: sup.status()["result"] == "ok" and sup.status()["restarts"] >= 0, timeout=3)
        ok = sup.status()["result"] == "ok"
        await sup.aclose()
        return ok, calls["n"]

    ok, n = asyncio.run(scenario())
    assert ok and n >= 2  # crashed once, re-kicked, then succeeded


def test_supervisor_unrecoverable_stops():
    async def scenario():
        async def work():
            raise RuntimeError("always")

        sup = supervise(work, name="t", loop=True, breath=0.01, interval=0.05, on_crash=lambda r: False)
        sup.start()
        await _poll(lambda: not sup.status()["want_running"], timeout=3)
        st = sup.status()
        await sup.aclose()
        return st

    st = asyncio.run(scenario())
    assert st["want_running"] is False and st["running"] is False


def test_supervisor_operator_stop_no_rekick():
    async def scenario():
        async def work():
            await asyncio.sleep(10)

        sup = supervise(work, name="t", loop=True, interval=0.05)
        sup.start()
        await _poll(lambda: sup.running())
        sup.stop()
        await _poll(lambda: not sup.running())
        # give the watchdog a couple ticks to (not) re-kick
        await asyncio.sleep(0.2)
        st = sup.status()
        await sup.aclose()
        return st

    st = asyncio.run(scenario())
    assert st["running"] is False and st["want_running"] is False
