"""Parser for maigret OSINT username search output.

Maigret prints each found account as ``[+] <Site>: <url>`` followed by indented
``├─key: value`` metadata. We capture the account rows as generic findings so
they land in the target store alongside everything else.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

# [+] GitHubGist [GitHub]: https://gist.github.com/johnsmith
_FOUND_RE = re.compile(r"^\[\+\]\s+(?P<site>.+?):\s+(?P<url>https?://\S+)\s*$")
# Header: "maigret: 3 account(s) found for 'johnsmith'"
_USERNAME_RE = re.compile(r"found for\s+'(?P<username>[^']+)'")


def parse_search(raw: str, store: "TargetStore") -> list[dict]:
    """Extract found accounts (site + profile URL) from maigret output, keyed to
    the searched username so they correlate to the person in the target store."""
    um = _USERNAME_RE.search(raw)
    username = um.group("username").strip() if um else ""
    if not username:
        # No parsed username → don't emit anonymous (target="") account findings.
        return []
    entities: list[dict] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        match = _FOUND_RE.match(line.strip())
        if not match:
            continue
        site = match.group("site").strip()
        if site.lower().startswith("using sites database"):
            continue
        url = match.group("url")
        if url in seen:
            continue
        seen.add(url)
        entities.append(
            {
                "type": "account",
                "category": "osint-account",
                "severity": "info",
                "target": username,
                "title": site,
                "value": url,
                "site": site,
                "url": url,
                "source": "maigret",
            }
        )
    return entities


PARSER_MAP[("maigret", "search")] = parse_search
