"""Parser for holehe email→accounts output.

Each ``[+] <site>`` line is a site where the email is registered. We capture one
account finding per site, keyed to the email, so they land in the target store
and correlate to the person (alongside maigret's username accounts).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

# Header: "holehe: 21 site(s) with an account for test@gmail.com"
_EMAIL_RE = re.compile(r"for\s+(?P<email>\S+@\S+)")
# "[+] amazon.com"
_USED_RE = re.compile(r"^\[\+\]\s+(?P<site>\S+)")


def parse_search(raw: str, store: "TargetStore") -> list[dict]:
    """Extract sites where the email is registered as account findings."""
    if not raw or raw.startswith("[timeout]"):
        return []
    em = _EMAIL_RE.search(raw)
    email = em.group("email").strip() if em else ""

    entities: list[dict] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        um = _USED_RE.match(line.strip())
        if not um:
            continue
        site = um.group("site").strip().rstrip(".,")
        if not site or site in seen:
            continue
        seen.add(site)
        entities.append(
            {
                "type": "account",
                "category": "osint-account",
                "severity": "info",
                "target": email,
                "title": site,
                "value": email,
                "site": site,
                "source": "holehe",
            }
        )
    return entities


PARSER_MAP[("holehe", "search")] = parse_search
