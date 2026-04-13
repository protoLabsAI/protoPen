#!/usr/bin/env python3
"""Standalone playbook runner — direct tool dispatch, no langchain required.

Usage:
    python run_playbook.py <playbook_name> --target <target> [--var key=val ...]

Examples:
    python run_playbook.py full_recon --target mush.bike
    python run_playbook.py web_vuln_assessment --target mush.bike --var url=https://mush.bike
    python run_playbook.py purple_team_exercise --target mush.bike
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("run_playbook")

# ── Tool registry (direct instantiation, no langchain) ─────────────────────

_TOOL_INSTANCES: dict[str, object] = {}


def _get_tool(tool_name: str):
    """Lazy-load and cache tool instances by name."""
    if tool_name in _TOOL_INSTANCES:
        return _TOOL_INSTANCES[tool_name]

    # Map playbook tool names → module.class
    TOOL_MAP = {
        "blackarch":           ("tools.blackarch",           "BlackArchTool"),
        "dns_enum":            ("tools.dns_enum",            "DnsEnumTool"),
        "subdomain_discovery": ("tools.subdomain_discovery", "SubdomainDiscoveryTool"),
        "osint_recon":         ("tools.osint_recon",         "OsintReconTool"),
        "web_enum":            ("tools.web_enum",            "WebEnumTool"),
        "ssl_audit":           ("tools.ssl_audit",           "SslAuditTool"),
        "vuln_scan":           ("tools.vuln_scan",           "VulnScanTool"),
        "web_vuln":            ("tools.web_vuln",            "WebVulnTool"),
        "sql_test":            ("tools.sql_test",            "SqlTestTool"),
        "cve_match":           ("tools.cve_match",           "CveMatchTool"),
        "cis_audit":           ("tools.cis_audit",           "CisAuditTool"),
        "hardening_check":     ("tools.hardening_check",     "HardeningCheckTool"),
        "purple_team":         ("tools.purple_team",         "PurpleTeamTool"),
        "api_enum":            ("tools.api_enum",            "ApiEnumTool"),
        "ssrf_detect":         ("tools.ssrf_detect",         "SsrfDetectTool"),
        "jwt_tool":            ("tools.jwt_tool",            "JwtTool"),
        "graphql_test":        ("tools.graphql_test",        "GraphqlTestTool"),
        "auth_test":           ("tools.auth_test",           "AuthTestTool"),
        "rate_limit":          ("tools.rate_limit",          "RateLimitTool"),
    }

    if tool_name not in TOOL_MAP:
        return None

    module_path, class_name = TOOL_MAP[tool_name]
    import importlib
    mod = importlib.import_module(module_path)
    cls = getattr(mod, class_name)
    instance = cls()
    _TOOL_INSTANCES[tool_name] = instance
    return instance


async def dispatch(tool_name: str, action: str, params: dict) -> str:
    """Direct tool dispatch — instantiate tool class and call execute()."""
    tool = _get_tool(tool_name)
    if tool is None:
        return json.dumps({"error": f"Tool '{tool_name}' not found"})
    # All tools accept action as a kwarg; some only accept **kwargs
    return await tool.execute(action=action, **params)


async def run(playbook_name: str, variables: dict[str, str]) -> None:
    from playbooks.loader import load_playbook
    from playbooks.runner import run_playbook
    from playbooks.schema import StepStatus

    pb = load_playbook(playbook_name, variables)
    total = len(pb.steps)
    start = time.time()

    print(f"\n{'='*60}")
    print(f"▶ Playbook: {pb.name}")
    print(f"  Target:   {variables.get('target', 'n/a')}")
    print(f"  Steps:    {total}")
    print(f"{'='*60}\n")

    def on_step(step):
        icon = "✅" if step.status == StepStatus.COMPLETED else "❌"
        elapsed = time.time() - start
        print(f"  {icon} [{elapsed:6.1f}s] {step.name} ({step.tool}.{step.action})")
        if step.status == StepStatus.FAILED and step.error:
            print(f"           Error: {step.error[:120]}")

    await run_playbook(pb, dispatch, on_step_complete=on_step)

    elapsed = time.time() - start
    completed = sum(1 for s in pb.steps if s.status == StepStatus.COMPLETED)
    failed = sum(1 for s in pb.steps if s.status == StepStatus.FAILED)

    print(f"\n{'─'*60}")
    print(f"  Done in {elapsed:.1f}s — {completed}/{total} passed, {failed} failed")
    print(f"{'─'*60}\n")

    # Dump step outputs
    for step in pb.steps:
        print(f"\n{'━'*60}")
        print(f"📋 {step.name} ({step.tool}.{step.action}) — {step.status.value}")
        print(f"{'━'*60}")
        if step.output:
            # Truncate very long outputs for readability
            out = step.output
            if len(out) > 5000:
                out = out[:5000] + f"\n... [truncated, {len(step.output)} chars total]"
            print(out)
        elif step.error:
            print(f"ERROR: {step.error}")
        else:
            print("(no output)")


def main():
    parser = argparse.ArgumentParser(description="Run a protoPen playbook directly")
    parser.add_argument("playbook", help="Playbook name (e.g. full_recon)")
    parser.add_argument("--target", required=True, help="Target host/domain")
    parser.add_argument("--var", action="append", default=[],
                        help="Extra variables as key=value")
    args = parser.parse_args()

    variables = {"target": args.target}
    for v in args.var:
        k, _, val = v.partition("=")
        variables[k] = val

    asyncio.run(run(args.playbook, variables))


if __name__ == "__main__":
    main()
