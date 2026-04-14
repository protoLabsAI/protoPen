"""Output parser registry and dispatcher.

Each parser: parse(raw: str, store: TargetStore) -> list[dict]
Parsers are registered in PARSER_MAP keyed by (tool_name, action).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

logger = logging.getLogger(__name__)

# Populated by parser module imports below
PARSER_MAP: dict[tuple[str, str], callable] = {}


def ingest_output(
    tool_name: str,
    action: str,
    raw: str,
    store: "TargetStore | None",
) -> list[dict]:
    """Route tool output through the matching parser; return ingested entities.

    Never raises — parser errors are logged and swallowed.
    """
    if store is None:
        return []
    parser = PARSER_MAP.get((tool_name, action))
    if parser is None:
        return []
    try:
        return parser(raw, store)
    except Exception:
        logger.exception("Parser failed for %s/%s", tool_name, action)
        return []


# ---- register parsers (imports trigger registration) ----
from tools.parsers import nmap_xml  # noqa: E402,F401
from tools.parsers import bettercap  # noqa: E402,F401
from tools.parsers import marauder_wifi  # noqa: E402,F401
from tools.parsers import flipper_rf  # noqa: E402,F401
from tools.parsers import dns_enum  # noqa: E402,F401
from tools.parsers import subdomain  # noqa: E402,F401
from tools.parsers import osint  # noqa: E402,F401
from tools.parsers import web_enum  # noqa: E402,F401
from tools.parsers import service_enum  # noqa: E402,F401
from tools.parsers import ssl_audit  # noqa: E402,F401
from tools.parsers import vuln_scan  # noqa: E402,F401
from tools.parsers import sql_test  # noqa: E402,F401
from tools.parsers import cve_match  # noqa: E402,F401
from tools.parsers import msf_exploit  # noqa: E402,F401
from tools.parsers import credential_attack  # noqa: E402,F401
from tools.parsers import hashcat_rules  # noqa: E402,F401
from tools.parsers import priv_esc  # noqa: E402,F401
from tools.parsers import lateral_move  # noqa: E402,F401
from tools.parsers import jwt_tool  # noqa: E402,F401
from tools.parsers import ssrf_detect  # noqa: E402,F401
from tools.parsers import auth_test  # noqa: E402,F401
from tools.parsers import graphql_test  # noqa: E402,F401

# Blue-team parsers (Phase 5)
from tools.parsers import cis_audit  # noqa: E402,F401
from tools.parsers import net_monitor  # noqa: E402,F401
from tools.parsers import hardening_check  # noqa: E402,F401
from tools.parsers import ir_toolkit  # noqa: E402,F401

# Container/K8s audit
from tools.parsers import container_audit  # noqa: E402,F401

# WebSocket testing
from tools.parsers import websocket_test  # noqa: E402,F401

# Tier 2 — CI/CD, IPv6, IoT, AD
from tools.parsers import cicd_audit  # noqa: E402,F401
from tools.parsers import ipv6_attack  # noqa: E402,F401
from tools.parsers import iot_protocol  # noqa: E402,F401
from tools.parsers import ad_attack  # noqa: E402,F401

# Tier 3 — LLM, Telecom, Evasion, Phishing, gRPC, Auth
from tools.parsers import llm_audit  # noqa: E402,F401
from tools.parsers import telecom_attack  # noqa: E402,F401
from tools.parsers import evasion  # noqa: E402,F401
from tools.parsers import phishing  # noqa: E402,F401
from tools.parsers import grpc_audit  # noqa: E402,F401
from tools.parsers import auth_audit  # noqa: E402,F401
from tools.parsers import sdn_attack  # noqa: E402,F401
from tools.parsers import mobile_audit  # noqa: E402,F401
from tools.parsers import serverless_audit  # noqa: E402,F401
from tools.parsers import lan_scan  # noqa: E402,F401
