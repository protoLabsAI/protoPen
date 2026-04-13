"""Parser for sqlmap output."""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

_PARAM_RE = re.compile(r"Parameter:\s+(\S+)\s+\((\w+)\)")
_BACKEND_RE = re.compile(r"back-end DBMS:\s+(.*)", re.IGNORECASE)
_DB_RE = re.compile(r"^\[\*\]\s+(\S+)", re.MULTILINE)


def parse_sqlmap(raw: str, store: "TargetStore") -> list[dict]:
    """Parse sqlmap text output — extract injectable params, backend, DBs."""
    entities: list[dict] = []
    for m in _PARAM_RE.finditer(raw):
        entities.append({
            "type": "sqli_param",
            "parameter": m.group(1),
            "injection_type": m.group(2),
        })
    m = _BACKEND_RE.search(raw)
    if m:
        entities.append({"type": "backend_dbms", "dbms": m.group(1).strip()})
    for m in _DB_RE.finditer(raw):
        entities.append({"type": "database", "name": m.group(1)})
    return entities


PARSER_MAP[("sql_test", "sqli_detect")] = parse_sqlmap
PARSER_MAP[("sql_test", "sqli_forms")] = parse_sqlmap
PARSER_MAP[("sql_test", "sqli_dbs")] = parse_sqlmap
PARSER_MAP[("sql_test", "sqli_tables")] = parse_sqlmap
