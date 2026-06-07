"""Subagents run under the enforcement + audit rail (upstream #638 adapted).

protoPen's engagement mode/scope gate (EnforcementMiddleware) must cover delegated
subagent tool calls, not just the lead — else a `task` delegation could run an
active/redteam tool while the engagement is PASSIVE, bypassing the ceiling and the
audit trail. These guard the wiring (`_subagent_middleware`) so it can't regress.
"""

from types import SimpleNamespace

from graph.middleware.audit import AuditMiddleware
from graph.middleware.enforcement import EnforcementMiddleware


def test_subagent_middleware_puts_enforcement_first_when_enabled():
    import graph.agent as agent

    config = SimpleNamespace(enforcement_middleware=True, enforcement_max_phase="", audit_middleware=True)
    mw = agent._subagent_middleware(config)
    # Enforcement must run BEFORE audit (block before record), mirroring the lead.
    assert isinstance(mw[0], EnforcementMiddleware)
    assert any(isinstance(m, AuditMiddleware) for m in mw)


def test_subagent_middleware_is_audit_only_when_enforcement_off():
    import graph.agent as agent

    config = SimpleNamespace(enforcement_middleware=False, enforcement_max_phase="", audit_middleware=True)
    mw = agent._subagent_middleware(config)
    assert [type(m).__name__ for m in mw] == ["AuditMiddleware"]


def test_subagent_middleware_honors_audit_flag():
    """Audit is gated by config.audit_middleware, same as the lead — both off → no rail."""
    import graph.agent as agent

    config = SimpleNamespace(enforcement_middleware=False, enforcement_max_phase="", audit_middleware=False)
    assert agent._subagent_middleware(config) == []


def test_production_subagents_do_not_use_unmiddlewared_react_agent():
    """The two production subagent builders (the `task` tool + the operator manual
    runner) must build via create_agent (middleware-capable), not the bare
    create_react_agent that bypassed the rail. Source-level regression guard."""
    import inspect

    import graph.agent as agent

    src = inspect.getsource(agent._build_task_tool) + inspect.getsource(agent.run_manual_subagent)
    assert "create_react_agent" not in src, "a production subagent reverted to the un-gated builder"
    assert src.count("_subagent_middleware(config)") >= 2
