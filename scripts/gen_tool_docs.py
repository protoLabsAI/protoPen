#!/usr/bin/env python3
"""Generate the tool catalog from the live tool registry.

The catalog is derived from ``get_combined_tools()`` — the same registry the
agent loads at runtime — so adding or removing a tool keeps the docs in sync
automatically. The same generated block is spliced into every file in TARGETS
(the README and the docs-site reference page). Run after changing the tool set:

    python scripts/gen_tool_docs.py            # rewrite every target in place
    python scripts/gen_tool_docs.py --check    # CI: fail if any target is stale
    python scripts/gen_tool_docs.py --print    # print the block to stdout

Tools are grouped by the CATEGORIES map below. A tool that is registered but
not listed in any category lands in an "Uncategorized" section and emits a
warning — that's the nudge to slot new tools into the right group.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# Force the Discord tool's env gate on so the catalog is identical whether or
# not Discord is configured in the environment running this script. Constructing
# the tool does no network I/O — the gate only checks for the var's presence.
os.environ.setdefault("DISCORD_ALERT_WEBHOOK", "https://example.invalid/docs-gen")

REPO_ROOT = Path(__file__).resolve().parent.parent
# Importable as `tools.*` no matter the working directory or how it's invoked
# (running a script puts its own dir on sys.path, not the repo root).
sys.path.insert(0, str(REPO_ROOT))
BEGIN = "<!-- BEGIN GENERATED TOOLS — run: python scripts/gen_tool_docs.py -->"
END = "<!-- END GENERATED TOOLS -->"

# Every file that embeds the catalog between the markers above.
TARGETS = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "docs" / "reference" / "tools.md",
]

# Ordered category -> tool names. Order here is the order rendered in the README.
CATEGORIES: list[tuple[str, list[str]]] = [
    (
        "Threat Intelligence & Research",
        [
            "cve_search",
            "security_feeds",
            "github_trending",
            "browser",
            "lab_monitor",
            "security_memory",
            "discord_feed",
        ],
    ),
    (
        "Reconnaissance & OSINT",
        [
            "external_recon",
            "dns_enum",
            "subdomain_discovery",
            "osint_recon",
            "maigret",
            "phoneinfoga",
            "holehe",
            "recon_pipeline",
        ],
    ),
    (
        "Network Enumeration",
        [
            "blackarch",
            "lan_scan",
            "service_enum",
            "web_enum",
            "api_enum",
            "ssl_audit",
            "perimeter_audit",
            "ipv6_attack",
        ],
    ),
    (
        "Vulnerability Assessment",
        [
            "vuln_scan",
            "sql_test",
            "web_vuln",
            "cve_match",
            "ssrf_detect",
            "rate_limit",
        ],
    ),
    (
        "Web, API & Auth Testing",
        [
            "jwt_tool",
            "auth_test",
            "auth_audit",
            "graphql_test",
            "grpc_audit",
            "websocket_test",
            "spa_test",
        ],
    ),
    (
        "Exploitation & Post-Exploitation",
        [
            "msf_exploit",
            "credential_attack",
            "hashcat_rules",
            "ad_attack",
            "priv_esc",
            "lateral_move",
            "data_exfil",
            "persistence",
            "cleanup",
            "evasion",
            "phishing",
        ],
    ),
    (
        "Wireless, RF & Hardware",
        [
            "device_manager",
            "portapack",
            "flipper",
            "marauder",
            "wifi_intel",
        ],
    ),
    (
        "Specialized Domains",
        [
            "iot_protocol",
            "iot_audit",
            "mobile_audit",
            "telecom_attack",
            "supply_chain",
            "serverless_audit",
            "cicd_audit",
            "sdn_attack",
            "llm_audit",
            "container_audit",
        ],
    ),
    (
        "Traffic Analysis & Network Monitoring",
        [
            "traffic_analysis",
            "net_monitor",
        ],
    ),
    (
        "Blue Team / Defensive",
        [
            "cis_audit",
            "hardening_check",
            "ir_toolkit",
            "purple_team",
        ],
    ),
    (
        "Engagement & Orchestration",
        [
            "engagement",
            "target_intel",
            "opsec",
            "playbook",
            "orchestrator",
            "chain_planner",
            "technique_library",
            "schedule_task",
            "list_schedules",
            "cancel_schedule",
            "wait",
            "create_task",
            "list_tasks",
            "update_task",
            "close_task",
            "set_goal",
            "request_user_input",
            "request_approval",
        ],
    ),
]


def one_line(desc: str) -> str:
    """Collapse a tool description to a single table-safe sentence."""
    desc = re.sub(r"\s+", " ", (desc or "").strip())
    first = re.split(r"(?<=[.])\s", desc)[0].strip().rstrip(".")
    if len(first) > 140:
        first = first[:137].rstrip() + "…"
    return first.replace("|", r"\|")


def load_registry() -> dict[str, str]:
    """Return {tool_name: description} from the live combined registry."""
    from tools.lg_tools import get_combined_tools

    registry: dict[str, str] = {}
    for tool in get_combined_tools():
        name = getattr(tool, "name", None) or getattr(tool, "__name__", None)
        if not name:
            continue
        registry[name] = getattr(tool, "description", "") or ""
    return registry


def render(registry: dict[str, str]) -> str:
    """Render the grouped markdown tool catalog."""
    seen: set[str] = set()
    lines: list[str] = [
        BEGIN,
        "",
        f"_{len(registry)} tools, generated from the live registry — do not edit by hand._",
        "",
    ]
    for title, names in CATEGORIES:
        rows = [(n, registry[n]) for n in names if n in registry]
        if not rows:
            continue
        lines += [f"### {title}", "", "| Tool | Description |", "|---|---|"]
        for name, desc in rows:
            seen.add(name)
            lines.append(f"| `{name}` | {one_line(desc)} |")
        lines.append("")

    leftover = sorted(set(registry) - seen)
    if leftover:
        sys.stderr.write(
            "warning: uncategorized tools (add them to CATEGORIES in "
            f"scripts/gen_tool_docs.py): {', '.join(leftover)}\n"
        )
        lines += ["### Uncategorized", "", "| Tool | Description |", "|---|---|"]
        for name in leftover:
            lines.append(f"| `{name}` | {one_line(registry[name])} |")
        lines.append("")

    lines.append(END)
    return "\n".join(lines)


def splice(path: Path, text: str, block: str) -> str:
    """Replace the region between the markers (inclusive) with ``block``."""
    pattern = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.DOTALL)
    if not pattern.search(text):
        raise SystemExit(f"markers not found in {path} — add a block bounded by:\n  {BEGIN}\n  {END}")
    return pattern.sub(lambda _: block, text)


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "--write"
    block = render(load_registry())

    if mode == "--print":
        print(block)
        return 0

    stale = False
    for path in TARGETS:
        current = path.read_text()
        updated = splice(path, current, block)
        if mode == "--check":
            if current != updated:
                stale = True
                sys.stderr.write(f"{path} tool catalog is stale — run: python scripts/gen_tool_docs.py\n")
        elif current != updated:
            path.write_text(updated)
            print(f"Updated tool catalog in {path}.")
        else:
            print(f"{path} tool catalog already up to date.")

    if mode == "--check":
        if stale:
            return 1
        print("Tool catalog is up to date in all targets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
