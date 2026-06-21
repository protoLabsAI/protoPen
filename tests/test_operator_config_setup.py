"""Setup-wizard backend: route wiring + the BYO-key persistence round-trip."""

from __future__ import annotations

import os

import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from graph.config import LangGraphConfig
from operator_api import config_setup
from operator_api.routes import register_operator_routes


# ── route layer (mirrors tests/test_operator_api_routes.py) ──────────────────


def _client(**config_callbacks):
    app = FastAPI()

    async def _run(req):
        return "ok"

    register_operator_routes(
        app,
        runtime_status=lambda: {"graph_loaded": True},
        subagent_list=lambda: [],
        subagent_run=_run,
        subagent_batch=_run,
        **config_callbacks,
    )
    return TestClient(app)


def test_config_routes_unwired_degrade_gracefully() -> None:
    client = _client()
    # setup-status defaults to complete so the wizard never blocks an un-wired build
    assert client.get("/api/config/setup-status").json() == {"setup_complete": True, "presets": []}
    assert client.get("/api/config").status_code == 409
    assert client.get("/api/config/presets/SOUL").status_code == 409
    assert client.post("/api/config/models", json={"api_base": "x"}).json()["error"]
    assert client.post("/api/config/setup", json={}).status_code == 409


def test_config_routes_wired_pass_through() -> None:
    seen = {}

    def models(api_base, api_key):
        seen["args"] = (api_base, api_key)
        return {"models": ["m1", "m2"], "error": ""}

    def setup(payload):
        seen["payload"] = payload
        return {"ok": True, "message": "saved"}

    client = _client(
        config_setup_status=lambda: {"setup_complete": False, "presets": ["SOUL"]},
        config_get=lambda: {"config": {"model": {"name": "m1"}}, "soul": "hi"},
        config_preset=lambda name: {"name": name, "content": "# soul"},
        config_models=models,
        config_setup=setup,
    )

    assert client.get("/api/config/setup-status").json()["setup_complete"] is False
    assert client.get("/api/config").json()["soul"] == "hi"
    assert client.get("/api/config/presets/SOUL").json() == {"name": "SOUL", "content": "# soul"}

    body = client.post("/api/config/models", json={"api_base": "http://g/v1", "api_key": "k"}).json()
    assert body["models"] == ["m1", "m2"]
    assert seen["args"] == ("http://g/v1", "k")

    out = client.post("/api/config/setup", json={"config": {"model": {"name": "m2"}}, "soul": "s"})
    assert out.json() == {"ok": True, "message": "saved"}
    assert seen["payload"]["soul"] == "s"


def test_preset_route_maps_missing_to_404_and_traversal_to_400() -> None:
    def preset(name):
        if name == "missing":
            raise FileNotFoundError("preset not found")
        raise ValueError("invalid preset name")

    client = _client(config_preset=preset)
    assert client.get("/api/config/presets/missing").status_code == 404
    assert client.get("/api/config/presets/evil").status_code == 400


# ── module layer (persistence round-trip) ────────────────────────────────────


def _use_tmp_config_dir(monkeypatch, tmp_path):
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    monkeypatch.setattr(config_setup, "resolve_config_dir", lambda: cfg_dir)
    return cfg_dir


def test_is_setup_complete_signals(monkeypatch, tmp_path) -> None:
    cfg_dir = _use_tmp_config_dir(monkeypatch, tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    assert config_setup.is_setup_complete(graph_config=LangGraphConfig()) is False

    # a configured key file flips it
    config_setup._write_key(config_setup.key_file_path(cfg_dir), "sk-local")
    assert config_setup.is_setup_complete(graph_config=LangGraphConfig()) is True


def test_env_key_wins_over_local_file(monkeypatch, tmp_path) -> None:
    cfg_dir = _use_tmp_config_dir(monkeypatch, tmp_path)
    config_setup._write_key(config_setup.key_file_path(cfg_dir), "sk-local")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fleet")

    # env/Infisical key present → local file is NOT promoted
    assert config_setup.load_local_key_into_env(cfg_dir, "http://x/v1") is False
    assert os.environ["OPENAI_API_KEY"] == "sk-fleet"
    assert config_setup.is_setup_complete(graph_config=LangGraphConfig()) is True


def test_load_local_key_into_env_promotes_and_sets_base(monkeypatch, tmp_path) -> None:
    cfg_dir = _use_tmp_config_dir(monkeypatch, tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    config_setup._write_key(config_setup.key_file_path(cfg_dir), "sk-byo")

    assert config_setup.load_local_key_into_env(cfg_dir, "http://gw/v1") is True
    assert os.environ["OPENAI_API_KEY"] == "sk-byo"
    assert os.environ["OPENAI_BASE_URL"] == "http://gw/v1"


def test_run_setup_persists_config_key_and_soul(monkeypatch, tmp_path) -> None:
    cfg_dir = _use_tmp_config_dir(monkeypatch, tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    # avoid the heavy in-process graph rebuild — covered by live Deck verification
    monkeypatch.setattr(config_setup, "_reload_agent", lambda cd: "stub-reloaded")

    payload = {
        "config": {
            "model": {
                "provider": "openai",
                "name": "protolabs/reasoning",
                "api_base": "https://api.example/v1",
                "api_key": "sk-secret",
                "temperature": 0.2,
                "max_tokens": 8000,
                "max_iterations": 50,
            },
            "middleware": {"knowledge": True, "audit": False, "memory": True},
            "knowledge": {"db_path": "/sandbox/knowledge/agent.db", "top_k": 7},
            "identity": {"name": "pwndeck", "operator": "kj"},
        },
        "soul": "# pwnDeck soul\nbe sharp.",
    }
    result = config_setup.run_setup(payload)
    assert result == {"ok": True, "message": "stub-reloaded"}

    # config override written, with the secret scrubbed from the yaml
    doc = yaml.safe_load(config_setup.config_override_path(cfg_dir).read_text())
    assert doc["model"]["api_base"] == "https://api.example/v1"
    assert doc["model"]["name"] == "protolabs/reasoning"
    assert doc["model"]["api_key"] == ""
    assert doc["middleware"]["audit"] is False
    assert doc["knowledge"]["top_k"] == 7
    assert doc["identity"] == {"name": "pwndeck", "operator": "kj"}
    # a block the wizard never touches survives from the bundled config
    assert "compaction" in doc

    # key persisted to its own 0600 file, never the yaml
    key_file = config_setup.key_file_path(cfg_dir)
    assert key_file.read_text() == "sk-secret"
    assert oct(key_file.stat().st_mode)[-3:] == "600"

    # SOUL written to the workspace root (where graph/prompts.py reads it first)
    assert (cfg_dir.parent / "SOUL.md").read_text().startswith("# pwnDeck soul")

    # and the loaded override round-trips through the real config loader
    cfg = LangGraphConfig.from_yaml(config_setup.config_override_path(cfg_dir))
    assert cfg.api_base == "https://api.example/v1"
    assert cfg.identity_name == "pwndeck"
    assert cfg.audit_middleware is False
    # now setup reports complete (the key file exists)
    assert config_setup.is_setup_complete() is True


def test_run_setup_blank_key_preserves_existing(monkeypatch, tmp_path) -> None:
    cfg_dir = _use_tmp_config_dir(monkeypatch, tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(config_setup, "_reload_agent", lambda cd: "ok")
    config_setup._write_key(config_setup.key_file_path(cfg_dir), "sk-existing")

    # "leave blank to preserve current key" — no api_key in the payload
    config_setup.run_setup({"config": {"model": {"api_base": "https://api.example/v1"}}, "soul": ""})

    assert config_setup.key_file_path(cfg_dir).read_text() == "sk-existing"


def test_get_config_reflects_live_identity_and_hides_key(monkeypatch, tmp_path) -> None:
    _use_tmp_config_dir(monkeypatch, tmp_path)
    from runtime.state import STATE

    cfg = LangGraphConfig(
        identity_name="pwndeck",
        identity_operator="kj",
        api_base="https://api.example/v1",
        api_key="sk-should-not-leak",
        model_name="protolabs/reasoning",
    )
    monkeypatch.setattr(STATE, "graph_config", cfg)

    body = config_setup.get_config()
    assert body["config"]["identity"] == {"name": "pwndeck", "operator": "kj"}
    assert body["config"]["model"]["api_base"] == "https://api.example/v1"
    assert "api_key" not in body["config"]["model"]


def test_probe_models_success(monkeypatch) -> None:
    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"data": [{"id": "alpha"}, {"id": "beta"}, {"no_id": 1}]}

    monkeypatch.setattr("httpx.get", lambda url, headers=None, timeout=None: _Resp())
    out = config_setup.probe_models("https://api.example/v1/", "sk-x")
    assert out == {"models": ["alpha", "beta"], "error": ""}
