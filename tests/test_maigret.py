"""Maigret tool — output summarization and account parsing."""

from __future__ import annotations

from tools.maigret import MaigretTool
from tools.parsers.maigret import parse_search

SAMPLE = """[+] Using sites database: /x/resources/data.json (3155 sites)
[-] Starting a search on top 34 sites from the Maigret database...
[!] You can run search by full list of sites with flag `-a`
[*] Checking username johnsmith on:
[+] GitHub: https://github.com/johnsmith
 ├─uid: 296614
 └─fullname: John
[+] GitHubGist [GitHub]: https://gist.github.com/johnsmith
[+] Medium: https://medium.com/@johnsmith
"""


def test_summarize_counts_found_and_drops_chatter():
    out = MaigretTool._summarize("johnsmith", SAMPLE)
    assert out.startswith("maigret: 3 account(s) found for 'johnsmith'")
    # progress/header chatter is removed
    assert "Using sites database" not in out
    assert "[*] Checking" not in out
    assert "Starting a search" not in out
    # found accounts and their metadata are kept
    assert "https://github.com/johnsmith" in out
    assert "├─uid: 296614" in out


def test_summarize_no_results():
    out = MaigretTool._summarize("nobody", "[*] Checking username nobody on:\n")
    assert "no accounts found" in out


def test_summarize_passes_timeout_marker_through():
    assert MaigretTool._summarize("u", "[timeout] maigret exceeded 5s").startswith("[timeout]")


def test_parser_extracts_unique_accounts():
    entities = parse_search(SAMPLE, store=None)  # parser does not touch the store
    assert all(e["type"] == "account" for e in entities)
    assert {e["url"] for e in entities} == {
        "https://github.com/johnsmith",
        "https://gist.github.com/johnsmith",
        "https://medium.com/@johnsmith",
    }
    sites = {e["site"] for e in entities}
    assert "GitHub" in sites
    assert "GitHubGist [GitHub]" in sites


def test_parser_ignores_database_line():
    entities = parse_search("[+] Using sites database: /x/data.json (3155 sites)", store=None)
    assert entities == []
