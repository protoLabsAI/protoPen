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
from tools.parsers import nmap_xml      # noqa: E402,F401
from tools.parsers import bettercap     # noqa: E402,F401
from tools.parsers import marauder_wifi # noqa: E402,F401
from tools.parsers import flipper_rf    # noqa: E402,F401
