"""graph.sdk — host-free building blocks for autonomous/agentic engines.

A stable import surface for the reusable primitives an unattended engine needs,
kept separate from the host wiring so they stay pure-stdlib and directly testable
(ported from protoAgent's plugin SDK). Today protoPen has no external plugin
contract, so this is simply the convenient one-stop import for core code:

    from graph.sdk import (
        DecisionLog, telemetry, render_html,   # observability / provenance
        Knobs, make_knob_tools,                # bounded, reversible tuning surface
        Supervisor, supervise,                 # watchdog-backed background lifecycle
    )

Each primitive is documented in its own module (graph/telemetry.py, graph/knobs.py,
graph/supervisor.py).
"""

from __future__ import annotations

from graph.knobs import Knob, Knobs, make_knob_tools
from graph.supervisor import Supervisor, supervise
from graph.telemetry import DecisionLog, render_html, telemetry

__all__ = [
    "DecisionLog",
    "telemetry",
    "render_html",
    "Knob",
    "Knobs",
    "make_knob_tools",
    "Supervisor",
    "supervise",
]
