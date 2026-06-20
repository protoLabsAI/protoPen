# SDK Primitives (`graph.sdk`)

`graph/sdk.py` is a small set of **host-free building blocks** for autonomous /
agentic engines — pure-stdlib helpers an unattended background engine needs,
kept separate from protoPen's host wiring so they stay portable and directly
testable. Import them from `graph.sdk`:

```python
from graph.sdk import (
    Supervisor, supervise,            # watchdog-backed background lifecycle
    DecisionLog, telemetry, render_html,  # provenance + a themed status panel
    Knobs, make_knob_tools,           # bounded, reversible tuning surface
)
```

These power the [autonomy](/explanation/autonomy) layer (e.g. keeping a long
background engine alive) and are the seam a future engine plugin builds on.

## Supervisor — watchdog-backed background loop

Runs a unit of work back-to-back under a watchdog that **re-kicks** a crash,
**restarts** a stall, and **recovers** a known fault — so the loop survives
unattended. The caller supplies the work + predicates; the Supervisor owns the
lifecycle.

```python
engine = supervise(
    run_one_window,            # async () -> Any  (one unit of work)
    name="recon",
    interval=90,               # watchdog check period (s)
    progress=lambda: len(LOG), # a token that changes while progressing
    stall_check=lambda: not any_scan_in_flight(),  # confirm a real stall
    on_crash=recover,          # (result) -> bool: True = handled, re-kick
)
engine.start()                 # returns immediately; runs in the background
engine.status()                # {running, want_running, restarts, result, events, …}
engine.request_stop()          # graceful wind-down after the current unit
await engine.aclose()          # cancel + await (teardown / tests)
```

A stall needs **both** frozen `progress` (if set) **and** a truthy `stall_check`
(if set), so a legitimately long unit of work isn't false-tripped.

## DecisionLog + telemetry + render_html — provenance

The observability surface an unattended engine needs: a capped audit trail of
what the agent changed (and why), a standard telemetry envelope, and a
self-contained HTML panel for a console view.

```python
log = DecisionLog(cap=50)
log.record("tune", "scan_aggression: 3 → 1", reason="scope tightened")
log.entries(5)                 # newest-last list of {action, detail, **fields}

env = telemetry(
    status="running · 3 hosts · 1 critical",
    metrics={"hosts": 3, "findings": 7},
    hints=["unscanned subnet 10.0.2.0/24"],
    decisions=log,             # a DecisionLog or a list of dicts
    sections=[{"title": "Hosts", "columns": ["ip", "os"], "rows": [["10.0.0.1", "linux"]]}],
)
html = render_html(env, title="Recon")  # --pl-*-themed, self-contained, all values escaped
```

## Knobs — bounded, reversible tuning

A typed, clamped, logged control surface an LLM strategist can steer a
deterministic engine with — declared once, read live, with named presets.

```python
KNOBS = (Knobs()
         .define("scan_aggression", 2, lo=0, hi=5, help="0=passive .. 5=loud")
         .define("posture", "stealth", choices=["stealth", "balanced", "loud"]))
KNOBS.preset("smash-and-grab", {"scan_aggression": 5, "posture": "loud"}, blurb="speed over stealth")

KNOBS.get("scan_aggression")        # read live in the engine
KNOBS.set("scan_aggression", "1")   # typed-coerced + clamped + logged
KNOBS.apply_preset("smash-and-grab")
KNOBS.changes()                     # the change log

# Auto-generate the agent-facing tools (<prefix>_knobs / _tune / _preset):
tools = make_knob_tools(KNOBS, prefix="recon")
```

`set`/`apply_preset` return human-readable strings (unknown/invalid values come
back as text, not exceptions), and applying a preset resets to defaults first so
switching presets isn't cumulative.

::: tip
These are stdlib-only and unit-tested in isolation. `make_knob_tools` imports
langchain lazily, so importing `graph.sdk` never requires it.
:::
