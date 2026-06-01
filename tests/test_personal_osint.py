"""Personal-OSINT tools (phoneinfoga, holehe) + the engagement-gated playbook.

Pure: tool summarizers + subprocess hardening (no binary needed), the playbook's
``requires_engagement`` flag, and the operator gate enforcing it. No langchain.
"""

from __future__ import annotations

import asyncio
import sys

import pytest

from tools.holehe import HoleheTool
from tools.phoneinfoga import PhoneInfogaTool


def _run(coro):
    return asyncio.run(coro)


# ── phoneinfoga ───────────────────────────────────────────────────────────────


def test_phoneinfoga_summarize_keeps_details():
    raw = "Country: US (+1)\nCarrier: Verizon Wireless\nLine type: mobile\n"
    out = PhoneInfogaTool._summarize("+14155552671", raw)
    assert out.startswith("phoneinfoga: scan of +14155552671")
    assert "Verizon Wireless" in out and "Line type: mobile" in out


def test_phoneinfoga_summarize_empty_and_timeout():
    assert "no results" in PhoneInfogaTool._summarize("+1", "")
    assert PhoneInfogaTool._summarize("x", "[timeout] phoneinfoga exceeded 60s.").startswith("[timeout]")


def test_run_strips_ansi(tmp_path):
    # ANSI is stripped at the _run layer (before _summarize sees it).
    tool = PhoneInfogaTool(workspace=str(tmp_path))
    emit = [sys.executable, "-c", r"print('\x1b[32mCountry: US\x1b[0m')"]
    out = asyncio.run(tool._run(*emit, timeout=15))
    assert "\x1b[" not in out and out == "Country: US"


def test_phoneinfoga_not_installed_message(monkeypatch, tmp_path):
    monkeypatch.delenv("PHONEINFOGA_BIN", raising=False)
    monkeypatch.setattr("tools.phoneinfoga.shutil.which", lambda _n: None)
    out = _run(PhoneInfogaTool(workspace=str(tmp_path)).scan("+14155552671"))
    assert "not installed" in out and "PHONEINFOGA_BIN" in out


def test_phoneinfoga_requires_number(tmp_path):
    out = _run(PhoneInfogaTool(workspace=str(tmp_path)).execute(action="scan", number=""))
    assert "required" in out


# ── holehe ────────────────────────────────────────────────────────────────────


def test_holehe_summarize_counts_used():
    raw = "[+] twitter.com\n[+] spotify.com\n[-] github.com\n"
    out = HoleheTool._summarize("a@b.com", raw)
    assert out.startswith("holehe: 2 site(s) with an account for a@b.com")
    assert "twitter.com" in out and "github.com" not in out


def test_holehe_summarize_none():
    assert "none found" in HoleheTool._summarize("a@b.com", "")


def test_holehe_rejects_bad_email(tmp_path):
    out = _run(HoleheTool(workspace=str(tmp_path)).execute(action="search", email="not-an-email"))
    assert "valid 'email'" in out


def test_holehe_not_installed_message(monkeypatch, tmp_path):
    monkeypatch.delenv("HOLEHE_BIN", raising=False)
    monkeypatch.setattr("tools.holehe.shutil.which", lambda _n: None)
    out = _run(HoleheTool(workspace=str(tmp_path)).search("a@b.com"))
    assert "not installed" in out and "HOLEHE_BIN" in out


# ── subprocess hardening (kill-first on timeout) ──────────────────────────────


@pytest.mark.parametrize("cls", [PhoneInfogaTool, HoleheTool])
def test_run_timeout_kills_child(cls, tmp_path):
    tool = cls(workspace=str(tmp_path))
    sleeper = [sys.executable, "-c", "import time; time.sleep(120)"]

    async def go():
        return await asyncio.wait_for(tool._run(*sleeper, timeout=1), timeout=15)

    out = asyncio.run(go())
    assert out.startswith("[timeout]") and "exceeded 1s" in out


@pytest.mark.parametrize("cls", [PhoneInfogaTool, HoleheTool])
def test_run_returns_stdout(cls, tmp_path):
    tool = cls(workspace=str(tmp_path))
    echo = [sys.executable, "-c", "print('ok-osint')"]
    assert asyncio.run(tool._run(*echo, timeout=15)) == "ok-osint"


# ── playbook gate: passive tools, but engagement required ─────────────────────


def test_personal_osint_requires_engagement():
    from operator_api.playbooks import PlaybookGateError, _enforce_gate, _playbook_risk
    from playbooks.loader import load_playbook

    pb = load_playbook("personal_osint")
    assert pb.requires_engagement is True
    assert _playbook_risk(pb.steps, pb.tags) == 0  # tools are passive

    # No active engagement → blocked even though risk is 0.
    with pytest.raises(PlaybookGateError):
        _enforce_gate(pb, None)


def test_personal_osint_passes_with_engagement():
    from operator_api.playbooks import _enforce_gate
    from playbooks.loader import load_playbook

    pb = load_playbook("personal_osint")

    class _Eng:
        active_engagement = {"scope": "acme.com targetuser"}

        class mode:
            value = 0
            name = "PASSIVE"

    # Active engagement (passive mode is fine — risk 0) → allowed.
    assert _enforce_gate(pb, _Eng()) == "passive"
