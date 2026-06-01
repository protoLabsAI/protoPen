from __future__ import annotations

import subprocess

import pytest

from operator_api.beads import BeadsService, _resolve_br_bin


def _completed(args, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=args, returncode=returncode, stdout=stdout, stderr=stderr)


def test_resolve_br_bin_prefers_env_override(monkeypatch) -> None:
    monkeypatch.setenv("BEADS_BR_BIN", "/opt/br")
    assert _resolve_br_bin() == "/opt/br"


def test_resolve_br_bin_falls_back_to_cargo_dir(monkeypatch, tmp_path) -> None:
    """With nothing on PATH, a ~/.cargo/bin/br is still found — the case that
    bit us on the Deck, where the systemd PATH excludes user-local installs."""
    monkeypatch.delenv("BEADS_BR_BIN", raising=False)
    monkeypatch.setattr("operator_api.beads.shutil.which", lambda _name: None)
    cargo_bin = tmp_path / ".cargo" / "bin"
    cargo_bin.mkdir(parents=True)
    br = cargo_bin / "br"
    br.write_text("#!/bin/sh\n")
    br.chmod(0o755)
    monkeypatch.setattr("operator_api.beads.Path.home", classmethod(lambda _cls: tmp_path))
    assert _resolve_br_bin() == str(br)


def test_resolve_br_bin_last_resort_is_bare_name(monkeypatch) -> None:
    monkeypatch.delenv("BEADS_BR_BIN", raising=False)
    monkeypatch.setattr("operator_api.beads.shutil.which", lambda _name: None)
    monkeypatch.setattr("operator_api.beads.Path.is_file", lambda _self: False)
    assert _resolve_br_bin() == "br"


def test_missing_br_raises_actionable_error(monkeypatch, tmp_path) -> None:
    def boom(*_a, **_k):
        raise FileNotFoundError("br")

    monkeypatch.setattr("operator_api.beads.subprocess.run", boom)
    with pytest.raises(RuntimeError, match="cargo install beads_rust"):
        BeadsService(br_bin="br").list(str(tmp_path))


def test_beads_status_detects_uninitialized_store(monkeypatch, tmp_path) -> None:
    def fake_run(*args, **kwargs):
        return _completed(
            args[0],
            returncode=1,
            stderr='{"error":{"code":"NOT_INITIALIZED"}}',
        )

    monkeypatch.setattr("operator_api.beads.subprocess.run", fake_run)

    assert BeadsService(br_bin="br").status(str(tmp_path)) == {"initialized": False}


def test_beads_list_uses_br_json_and_filters_tombstones(monkeypatch, tmp_path) -> None:
    calls = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return _completed(
            args[0],
            stdout=('[{"id":"bd-1","status":"open"},{"id":"bd-2","status":"tombstone"}]'),
        )

    monkeypatch.setattr("operator_api.beads.subprocess.run", fake_run)

    issues = BeadsService(br_bin="br").list(str(tmp_path))

    assert issues == [{"id": "bd-1", "status": "open"}]
    assert calls[0][0][0] == ["br", "list", "--all", "--json"]
    assert calls[0][1]["cwd"] == str(tmp_path)
    assert calls[0][1]["env"]["RUST_LOG"] == "error"


def test_beads_create_builds_structured_command(monkeypatch, tmp_path) -> None:
    calls = []

    def fake_run(*args, **kwargs):
        calls.append(args[0])
        return _completed(args[0], stdout='{"id":"bd-1","title":"Task"}')

    monkeypatch.setattr("operator_api.beads.subprocess.run", fake_run)

    issue = BeadsService(br_bin="br").create(
        str(tmp_path),
        {
            "title": "Task",
            "type": "feature",
            "priority": 1,
            "description": "Details",
            "assignee": "agent",
        },
    )

    assert issue == {"id": "bd-1", "title": "Task"}
    assert calls[0] == [
        "br",
        "create",
        "Task",
        "--json",
        "--type",
        "feature",
        "--priority",
        "1",
        "--description",
        "Details",
        "--assignee",
        "agent",
    ]


def test_beads_update_close_delete_build_commands(monkeypatch, tmp_path) -> None:
    calls = []
    outputs = iter(
        [
            '{"id":"bd-1","status":"in_progress"}',
            '{"id":"bd-1","status":"closed"}',
            '{"deleted":"bd-1"}',
        ]
    )

    def fake_run(*args, **kwargs):
        calls.append(args[0])
        return _completed(args[0], stdout=next(outputs))

    monkeypatch.setattr("operator_api.beads.subprocess.run", fake_run)

    service = BeadsService(br_bin="br")
    assert service.update(
        str(tmp_path),
        "bd-1",
        {
            "title": "Next",
            "status": "in_progress",
            "priority": 1,
            "type": "task",
            "assignee": "agent",
        },
    ) == {"id": "bd-1", "status": "in_progress"}
    assert service.close(str(tmp_path), "bd-1", "done") == {"id": "bd-1", "status": "closed"}
    assert service.delete(str(tmp_path), "bd-1") == {"deleted": "bd-1"}

    assert calls == [
        [
            "br",
            "update",
            "bd-1",
            "--json",
            "--title",
            "Next",
            "--status",
            "in_progress",
            "--priority",
            "1",
            "--type",
            "task",
            "--assignee",
            "agent",
        ],
        ["br", "close", "bd-1", "--json", "--reason", "done"],
        ["br", "delete", "bd-1", "--json"],
    ]
