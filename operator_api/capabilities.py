"""Capabilities catalog for the operator console (protopen-1vd).

Reframes the agent's tool registry as a friendly, browseable catalog of what
protoPen can *do* — grouped into approachable categories (Wireless & RF, OSINT &
Recon, Scanning, …) rather than a flat 70-entry tool list. Read-only; mirrors
the live registry (``get_combined_tools``) so it never drifts from what the
agent can actually call. The categories are presentational — a Flipper-style
menu over the same tools the model sees.
"""

from typing import Any

# Keyword → category. First match wins, so order matters (more specific first).
# Matched against "name + summary", lower-cased. Purely presentational; tweak
# freely as the toolset grows.
_CATEGORY_RULES: list[tuple[str, tuple[str, ...]]] = [
    (
        "Wireless, RF & Hardware",
        (
            "wifi",
            "marauder",
            "flipper",
            "portapack",
            "deauth",
            "beacon",
            "bluetooth",
            " ble",
            "rfid",
            "nfc",
            "sub-ghz",
            "subghz",
            "wireless",
            "signal",
            "iot",
            "zigbee",
            "zwave",
            "hardware",
        ),
    ),
    (
        "OSINT & Recon",
        (
            "osint",
            "recon",
            "dns",
            "subdomain",
            "maigret",
            "holehe",
            "phoneinfoga",
            "phone",
            "whois",
            "external",
            "perimeter",
            "email",
            "username",
            "social",
            "breach",
        ),
    ),
    (
        "Scanning & Enumeration",
        (
            "nmap",
            "scan",
            "port",
            "nuclei",
            "enum",
            "smb",
            "crackmapexec",
            "nbtscan",
            "masscan",
            "service",
            "vuln",
            "discovery",
            "graphql",
            "rate_limit",
            "sqli",
            "xss",
            "fuzz",
            "sql",
            "websocket",
            "spa_",
            "http",
        ),
    ),
    (
        "Exploitation & Access",
        (
            "exploit",
            "metasploit",
            " msf",
            "payload",
            "crack",
            "hashcat",
            "john",
            "brute",
            "password",
            "shell",
            "attack",
            "lateral",
            "exfil",
            "privesc",
            "auth_test",
            "ad_",
            "sdn",
        ),
    ),
    (
        "Security Intel",
        (
            "cve",
            "feed",
            "advisory",
            "threat",
            "github",
            "exploitdb",
            "knowledge",
            "security_memory",
            "digest",
        ),
    ),
    (
        "Blue Team & Defense",
        (
            "cis",
            "harden",
            "audit",
            "monitor",
            "incident",
            "ir_",
            "purple",
            "defense",
            "net_monitor",
            "traffic",
        ),
    ),
    (
        "Targets & Findings",
        (
            "target",
            "finding",
            "engagement",
            "intel",
            "log_finding",
            "host",
        ),
    ),
    (
        "Agent & Automation",
        (
            "task",
            "workflow",
            "skill",
            "schedule",
            "orchestrat",
            "subagent",
            "browser",
            "search_tools",
            "delegate",
            "scheduler",
            "playbook",
            "set_goal",
            "goal",
            "approval",
            "request_user",
            "request_approval",
        ),
    ),
]
_DEFAULT_CATEGORY = "Other"


def _categorize(name: str, summary: str) -> str:
    hay = f" {name} {summary} ".lower()
    for label, keywords in _CATEGORY_RULES:
        if any(kw in hay for kw in keywords):
            return label
    return _DEFAULT_CATEGORY


def list_capabilities(store: Any = None) -> dict[str, Any]:
    """Catalog of the agent's callable tools, categorized. Returns
    ``{count, tools: [{name, summary, category}]}`` sorted by category then name.
    Degrades to an empty catalog rather than raising, so the console renders a
    "no capabilities" state instead of 500ing."""
    try:
        from tools.lg_tools import _tool_summary, get_combined_tools

        tools = get_combined_tools(store)
    except Exception as exc:  # noqa: BLE001
        print(f"[capabilities] tool registry unavailable: {exc}")
        return {"count": 0, "tools": []}

    items: list[dict[str, str]] = []
    for tool in tools:
        name = getattr(tool, "name", None)
        if not name:
            continue
        summary = _tool_summary(tool)
        items.append({"name": name, "summary": summary, "category": _categorize(name, summary)})

    items.sort(key=lambda item: (item["category"], item["name"]))
    return {"count": len(items), "tools": items}
