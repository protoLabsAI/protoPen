"""OSINT parsers (phoneinfoga, holehe, maigret) + the goal-verifier findings bridge.

Parsers turn tool output into target-store findings; the goal verifier merges
those (scoped to the engagement) so OSINT hits can satisfy `findings` goals.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from graph.goals.verifiers import _merge_findings
from tools.parsers import PARSER_MAP
from tools.parsers.holehe import parse_search as holehe_parse
from tools.parsers.maigret import parse_search as maigret_parse
from tools.parsers.phoneinfoga import parse_scan as phoneinfoga_parse

PHONE_OUT = """phoneinfoga: scan of +14155552671

Results for local
Raw local: 4155552671
Country: US (+1)
Carrier: Verizon Wireless
Line type: mobile
"""

HOLEHE_OUT = """holehe: 3 site(s) with an account for test@gmail.com

[+] Email used, [-] Email not used, [x] Rate limit
[+] amazon.com
[+] twitter.com
[+] amazon.com
"""

MAIGRET_OUT = """maigret: 2 account(s) found for 'johnsmith'

[+] GitHub: https://github.com/johnsmith
[+] Twitter: https://twitter.com/johnsmith
"""


# ── phoneinfoga parser ────────────────────────────────────────────────────────


def test_phoneinfoga_parser_extracts_profile():
    out = phoneinfoga_parse(PHONE_OUT, store=None)
    assert len(out) == 1
    f = out[0]
    assert f["type"] == "phone" and f["target"] == "+14155552671"
    assert f["country"] == "US (+1)" and f["carrier"] == "Verizon Wireless" and f["line_type"] == "mobile"
    assert f["category"] == "osint-phone"


def test_phoneinfoga_parser_ignores_timeout_and_empty():
    assert phoneinfoga_parse("[timeout] phoneinfoga exceeded 60s.", store=None) == []
    assert phoneinfoga_parse("phoneinfoga: scan of  — no results", store=None) == []


# ── holehe parser ─────────────────────────────────────────────────────────────


def test_holehe_parser_extracts_accounts_keyed_to_email():
    out = holehe_parse(HOLEHE_OUT, store=None)
    sites = {e["site"] for e in out}
    assert sites == {"amazon.com", "twitter.com"}  # deduped
    assert all(e["target"] == "test@gmail.com" and e["type"] == "account" for e in out)
    assert all(e["category"] == "osint-account" for e in out)


def test_holehe_parser_handles_none():
    assert holehe_parse("holehe: 0 site(s) ... — none found among the checked sites.", store=None) == []


def test_holehe_parser_drops_legend_line():
    # holehe's legend "[+] Email used, [-] ... [x] ..." must not become an account.
    out = holehe_parse("holehe: 0 site(s) for a@b.com\n\n[+] Email used, [-] Email not used, [x] Rate limit", store=None)
    assert out == []


# ── maigret parser (now keyed to the username) ────────────────────────────────


def test_maigret_parser_keys_accounts_to_username():
    out = maigret_parse(MAIGRET_OUT, store=None)
    assert len(out) == 2
    assert all(e["target"] == "johnsmith" for e in out)
    assert {e["site"] for e in out} == {"GitHub", "Twitter"}
    assert all(e["url"].startswith("https://") for e in out)


# ── registry ──────────────────────────────────────────────────────────────────


def test_parsers_registered():
    assert ("phoneinfoga", "scan") in PARSER_MAP
    assert ("holehe", "search") in PARSER_MAP
    assert ("maigret", "search") in PARSER_MAP


# ── goal-verifier findings bridge ─────────────────────────────────────────────


class _Store:
    def __init__(self, rows):
        self._rows = rows

    def get_findings(self, target="", tool=""):
        return list(self._rows)


def test_merge_findings_includes_recent_target_store():
    mgr = NS(
        findings=[{"severity": "high", "category": "vuln"}],
        active_engagement={"started_at": "2026-06-01T00:00:00+00:00"},
        target_store=_Store(
            [
                {"severity": "info", "category": "osint-account", "first_seen": "2026-06-01T12:00:00+00:00"},
                {"severity": "info", "category": "osint-account", "first_seen": "2026-05-01T00:00:00+00:00"},  # stale
            ]
        ),
    )
    merged = _merge_findings(mgr)
    # engagement finding + the one recent target-store finding (stale one excluded).
    assert len(merged) == 2
    cats = [f["category"] for f in merged]
    assert "vuln" in cats and cats.count("osint-account") == 1


def test_merge_findings_no_engagement_returns_logged_only():
    mgr = NS(findings=[{"severity": "low", "category": "x"}], active_engagement=None, target_store=_Store([]))
    assert _merge_findings(mgr) == [{"severity": "low", "category": "x"}]
    assert _merge_findings(None) == []
