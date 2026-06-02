"""Maigret tool — output summarization and account parsing."""

from __future__ import annotations

import asyncio
import sys

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
    # The parser receives the *summarized* output (that's what execute() ingests),
    # whose header carries the username it keys findings to.
    summarized = MaigretTool._summarize("johnsmith", SAMPLE)
    entities = parse_search(summarized, store=None)  # parser does not touch the store
    assert all(e["type"] == "account" and e["target"] == "johnsmith" for e in entities)
    assert {e["url"] for e in entities} == {
        "https://github.com/johnsmith",
        "https://gist.github.com/johnsmith",
        "https://medium.com/@johnsmith",
    }
    sites = {e["site"] for e in entities}
    assert "GitHub" in sites
    assert "GitHubGist [GitHub]" in sites


def test_run_timeout_kills_child_and_returns(tmp_path):
    """A hung subprocess must not wedge the turn: _run kills it and returns the
    timeout marker within the wall-clock cap (regression for the wait_for cancel
    hang)."""
    tool = MaigretTool(workspace=str(tmp_path))
    # A child that ignores SIGTERM-via-cancel and would otherwise outlive us.
    sleeper = [sys.executable, "-c", "import time; time.sleep(120)"]

    async def go():
        return await asyncio.wait_for(tool._run(*sleeper, timeout=1), timeout=15)

    out = asyncio.run(go())
    assert out.startswith("[timeout]")
    assert "exceeded 1s" in out


def test_run_returns_stdout_on_success(tmp_path):
    tool = MaigretTool(workspace=str(tmp_path))
    echo = [sys.executable, "-c", "print('hello-maigret')"]
    out = asyncio.run(tool._run(*echo, timeout=15))
    assert out == "hello-maigret"


def test_parser_ignores_database_line():
    entities = parse_search("[+] Using sites database: /x/data.json (3155 sites)", store=None)
    assert entities == []
