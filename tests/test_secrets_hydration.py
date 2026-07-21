"""External secrets-manager hydration (port protoAgent ADR 0080) — infra/secrets + the
from_yaml hook.

Covers the orchestrator's apply policy (existing-env-wins, ownership, protected vars,
removals, TTL/fingerprint gating, required escalation), the Infisical provider over an
httpx.MockTransport (login → v3-raw list, imports merge, 401 re-login, timeout), the
from_yaml wiring (hydrate-before-parse, inert when disabled), and sensitive-value pickup.
"""

from __future__ import annotations

import json
import os
import textwrap

import httpx
import pytest

import infra.secrets as ext
from infra.secrets import (
    ErrorKind,
    FetchResult,
    InfisicalProvider,
    SecretsProvider,
    SecretsRequiredError,
    SourceConfig,
    hydrate_from_docs,
    register_secrets_provider,
    sensitive_values,
)
from infra.secrets.hydrate import _reset_for_tests


class FakeProvider(SecretsProvider):
    name = "fake"
    bootstrap_env = ("FAKE_TOKEN",)

    def __init__(self):
        self.calls = 0
        self.values: dict[str, str] = {}
        self.result: FetchResult | None = None  # explicit failure override

    def fetch(self, cfg: SourceConfig) -> FetchResult:
        self.calls += 1
        if self.result is not None:
            return self.result
        return FetchResult(values=dict(self.values))


@pytest.fixture()
def fake(monkeypatch):
    """A registered fake provider + clean orchestrator state, torn down after."""
    provider = FakeProvider()
    register_secrets_provider(provider)
    _reset_for_tests()
    monkeypatch.setenv("FAKE_TOKEN", "bootstrap-cred")
    yield provider
    _reset_for_tests()
    ext.base._PROVIDERS.pop("fake", None)


def _docs(**sm) -> tuple[dict, dict]:
    section = {"enabled": True, "provider": "fake", "project_id": "p1", **sm}
    return {"secrets_manager": section}, {}


# ---------------------------------------------------------------------------
# Orchestrator apply policy
# ---------------------------------------------------------------------------


def test_apply_sets_and_owns_the_var(fake, monkeypatch):
    monkeypatch.delenv("HYDRATED_KEY", raising=False)
    fake.values = {"HYDRATED_KEY": "sk-manager-value-123"}
    status = hydrate_from_docs(*_docs())
    assert status is not None and status.ok
    assert os.environ["HYDRATED_KEY"] == "sk-manager-value-123"
    assert "sk-manager-value-123" in sensitive_values()  # available for redaction


def test_preexisting_env_shadows_by_default(fake, monkeypatch):
    monkeypatch.setenv("HYDRATED_KEY", "operator-set")
    fake.values = {"HYDRATED_KEY": "manager-value-123"}
    status = hydrate_from_docs(*_docs())
    assert os.environ["HYDRATED_KEY"] == "operator-set"  # env wins
    assert "HYDRATED_KEY" in status.shadowed


def test_override_env_prefers_the_manager(fake, monkeypatch):
    monkeypatch.setenv("HYDRATED_KEY", "operator-set")
    fake.values = {"HYDRATED_KEY": "manager-value-123"}
    hydrate_from_docs(*_docs(override_env=True))
    assert os.environ["HYDRATED_KEY"] == "manager-value-123"


def test_bootstrap_and_process_vars_are_protected(fake, monkeypatch):
    """A fetched value can never overwrite the provider's own bootstrap credential or
    the core process env (PATH/HOME/PYTHONPATH), even with override_env."""
    original_path = os.environ.get("PATH", "")
    fake.values = {
        "FAKE_TOKEN": "evil-overwrite",
        "PATH": "/evil/bin",
        "OK_VAR": "value-12345",
    }
    hydrate_from_docs(*_docs(override_env=True))
    assert os.environ["FAKE_TOKEN"] == "bootstrap-cred"
    assert os.environ["PATH"] == original_path
    assert os.environ["OK_VAR"] == "value-12345"


def test_invalid_names_and_blank_values_skipped(fake, monkeypatch):
    monkeypatch.delenv("OK_VAR", raising=False)
    fake.values = {"OK_VAR": "value-12345", "1BAD": "x", "has space": "y", "BLANK": ""}
    hydrate_from_docs(*_docs())
    assert os.environ["OK_VAR"] == "value-12345"
    assert "1BAD" not in os.environ and "BLANK" not in os.environ


def test_refresh_updates_and_removes_owned_only(fake, monkeypatch):
    monkeypatch.delenv("A_KEY", raising=False)
    monkeypatch.delenv("B_KEY", raising=False)
    fake.values = {"A_KEY": "a-12345678", "B_KEY": "b-12345678"}
    hydrate_from_docs(*_docs())
    assert os.environ["A_KEY"] == "a-12345678"
    # B vanishes from the manager on the next fetch → un-exported (we own it)
    fake.values = {"A_KEY": "a-updated-9"}
    hydrate_from_docs(*_docs(), force=True)
    assert os.environ["A_KEY"] == "a-updated-9"
    assert "B_KEY" not in os.environ


def test_ttl_gate_dedups_and_force_bypasses(fake):
    fake.values = {"K": "v-12345678"}
    hydrate_from_docs(*_docs())
    hydrate_from_docs(*_docs())  # same fingerprint, inside the window → no fetch
    assert fake.calls == 1
    hydrate_from_docs(*_docs(), force=True)
    assert fake.calls == 2
    hydrate_from_docs(*_docs(environment="staging"))  # fingerprint changed → refetch
    assert fake.calls == 3


def test_failure_warns_and_continues_by_default(fake, caplog):
    fake.result = FetchResult(error="down", error_kind=ErrorKind.NETWORK)
    status = hydrate_from_docs(*_docs())
    assert status is not None and not status.ok
    assert status.error_kind == "network"


def test_required_failure_raises(fake):
    fake.result = FetchResult(error="down", error_kind=ErrorKind.NETWORK)
    with pytest.raises(SecretsRequiredError):
        hydrate_from_docs(*_docs(required=True))


def test_unknown_provider_is_a_contained_error(fake):
    merged = {"secrets_manager": {"enabled": True, "provider": "nope", "project_id": "p1"}}
    status = hydrate_from_docs(merged, {})
    assert status is not None and not status.ok
    assert status.error_kind == "not_configured"


def test_disable_env_escape_hatch(fake, monkeypatch):
    monkeypatch.setenv("PROTOPEN_NO_SECRETS_HYDRATE", "1")
    assert hydrate_from_docs(*_docs()) is None
    assert fake.calls == 0


def test_bootstrap_creds_resolve_secrets_doc_first(fake):
    captured: dict = {}
    real_fetch = fake.fetch

    def spy(cfg):
        captured["cfg"] = cfg
        return real_fetch(cfg)

    fake.fetch = spy
    merged, _ = _docs(client_id="from-yaml")
    secrets_doc = {"secrets_manager": {"client_id": "from-secrets-doc", "client_secret": "s3cret"}}
    hydrate_from_docs(merged, secrets_doc, force=True)
    assert captured["cfg"].client_id == "from-secrets-doc"
    assert captured["cfg"].client_secret == "s3cret"


# ---------------------------------------------------------------------------
# from_yaml wiring — hydrate before parse, inert when absent/disabled
# ---------------------------------------------------------------------------


def _write_config(tmp_path, body: str):
    p = tmp_path / "langgraph-config.yaml"
    p.write_text(textwrap.dedent(body))
    return p


def test_from_yaml_hydrates_env_before_parse(fake, tmp_path, monkeypatch):
    from graph.config import LangGraphConfig

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    fake.values = {"OPENAI_API_KEY": "sk-from-manager-1"}
    p = _write_config(
        tmp_path,
        """
        model:
          api_base: http://gateway:4000/v1
        secrets_manager:
          enabled: true
          provider: fake
          project_id: p1
        """,
    )
    cfg = LangGraphConfig.from_yaml(p)
    # The manager populated the env tier; the lazy fallback in graph/llm.py picks it up.
    assert os.environ["OPENAI_API_KEY"] == "sk-from-manager-1"
    assert cfg.secrets_manager_enabled is True


def test_from_yaml_disabled_section_never_fetches(fake, tmp_path):
    from graph.config import LangGraphConfig

    p = _write_config(
        tmp_path,
        """
        secrets_manager:
          enabled: false
          provider: fake
        """,
    )
    cfg = LangGraphConfig.from_yaml(p)
    assert fake.calls == 0
    assert cfg.secrets_manager_enabled is False


def test_from_yaml_required_failure_propagates(fake, tmp_path):
    from graph.config import LangGraphConfig

    fake.result = FetchResult(error="down", error_kind=ErrorKind.NETWORK)
    p = _write_config(
        tmp_path,
        """
        secrets_manager:
          enabled: true
          provider: fake
          project_id: p1
          required: true
        """,
    )
    with pytest.raises(SecretsRequiredError):
        LangGraphConfig.from_yaml(p)


# ---------------------------------------------------------------------------
# Infisical provider over httpx.MockTransport
# ---------------------------------------------------------------------------


def _infisical_cfg(**kw) -> SourceConfig:
    base = dict(
        provider="infisical",
        host="https://infisical.test",
        project_id="proj-1",
        environment="prod",
        path="/agent",
        client_id="cid",
        client_secret="csec",
        timeout_seconds=5.0,
    )
    base.update(kw)
    return SourceConfig(**base)


def _mock_provider(handler) -> InfisicalProvider:
    return InfisicalProvider(transport=httpx.MockTransport(handler))


def test_infisical_happy_path_merges_imports_lower_precedence():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/auth/universal-auth/login":
            body = json.loads(request.content)
            seen["login"] = body
            return httpx.Response(200, json={"accessToken": "tok-1", "expiresIn": 3600})
        assert request.url.path == "/api/v3/secrets/raw"
        seen["params"] = dict(request.url.params)
        assert request.headers["Authorization"] == "Bearer tok-1"
        return httpx.Response(
            200,
            json={
                "secrets": [{"secretKey": "OPENAI_API_KEY", "secretValue": "sk-path-wins"}],
                "imports": [
                    {
                        "secrets": [
                            {"secretKey": "OPENAI_API_KEY", "secretValue": "sk-imported"},
                            {"secretKey": "EXTRA", "secretValue": "extra-value"},
                        ]
                    }
                ],
            },
        )

    result = _mock_provider(handler).fetch(_infisical_cfg())
    assert result.ok
    assert result.values == {"OPENAI_API_KEY": "sk-path-wins", "EXTRA": "extra-value"}
    assert seen["login"] == {"clientId": "cid", "clientSecret": "csec"}
    assert seen["params"]["workspaceId"] == "proj-1"
    assert seen["params"]["environment"] == "prod"
    assert seen["params"]["secretPath"] == "/agent"


def test_infisical_relogins_once_on_401():
    calls = {"login": 0, "list": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/auth/universal-auth/login":
            calls["login"] += 1
            return httpx.Response(200, json={"accessToken": f"tok-{calls['login']}", "expiresIn": 3600})
        calls["list"] += 1
        if request.headers["Authorization"] == "Bearer tok-1":
            return httpx.Response(401)
        return httpx.Response(200, json={"secrets": [{"secretKey": "K", "secretValue": "v-123456"}]})

    result = _mock_provider(handler).fetch(_infisical_cfg())
    assert result.ok and result.values == {"K": "v-123456"}
    assert calls == {"login": 2, "list": 2}


def test_infisical_login_rejected_is_auth_failed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "bad identity"})

    result = _mock_provider(handler).fetch(_infisical_cfg())
    assert not result.ok and result.error_kind == ErrorKind.AUTH_FAILED
    assert "csec" not in result.error  # never leak the credential


def test_infisical_timeout_maps_to_timeout_kind():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("slow")

    result = _mock_provider(handler).fetch(_infisical_cfg())
    assert not result.ok and result.error_kind == ErrorKind.TIMEOUT


def test_infisical_unconfigured_short_circuits():
    result = InfisicalProvider().fetch(_infisical_cfg(client_secret=""))
    assert not result.ok and result.error_kind == ErrorKind.NOT_CONFIGURED
    result = InfisicalProvider().fetch(_infisical_cfg(project_id=""))
    assert not result.ok and result.error_kind == ErrorKind.NOT_CONFIGURED


def test_infisical_token_cached_across_fetches():
    calls = {"login": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/auth/universal-auth/login":
            calls["login"] += 1
            return httpx.Response(200, json={"accessToken": "tok", "expiresIn": 3600})
        return httpx.Response(200, json={"secrets": []})

    provider = _mock_provider(handler)
    assert provider.fetch(_infisical_cfg()).ok
    assert provider.fetch(_infisical_cfg()).ok
    assert calls["login"] == 1


# --- CodeRabbit #283 hardening ---------------------------------------------


def test_non_dict_secrets_manager_does_not_crash_from_yaml(fake, tmp_path):
    """`secrets_manager: true` (a non-dict) must not crash config load."""
    from graph.config import LangGraphConfig

    p = _write_config(tmp_path, "secrets_manager: true\n")
    cfg = LangGraphConfig.from_yaml(p)  # must not raise
    assert cfg.secrets_manager_enabled is False
    assert fake.calls == 0


def test_cached_required_failure_still_reraises(fake):
    """A required source that failed must fail-fast on a repeated load INSIDE the TTL
    window too — the cache can't silently serve a half-configured agent."""
    fake.result = FetchResult(error="down", error_kind=ErrorKind.NETWORK)
    with pytest.raises(SecretsRequiredError):
        hydrate_from_docs(*_docs(required=True))
    # Second call is within the retry window (cached) — must still raise, not return.
    with pytest.raises(SecretsRequiredError):
        hydrate_from_docs(*_docs(required=True))
    assert fake.calls == 1  # the second call used the cache (no refetch) yet still raised


def test_rotated_out_value_purged_from_redaction_set(fake, monkeypatch):
    """A secret value that the manager stops returning is dropped from the redaction
    set (no unbounded growth / stale redaction)."""
    monkeypatch.delenv("ROTATING_KEY", raising=False)
    fake.values = {"ROTATING_KEY": "old-value-123456"}
    hydrate_from_docs(*_docs())
    assert "old-value-123456" in sensitive_values()
    fake.values = {"ROTATING_KEY": "new-value-789012"}
    hydrate_from_docs(*_docs(), force=True)
    assert "new-value-789012" in sensitive_values()
    assert "old-value-123456" not in sensitive_values()  # purged
