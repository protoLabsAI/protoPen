"""Console OAuth sign-in wiring for the native providers (ADR 0097).

Thin adapters over ``graph.providers.oauth_login`` + ``graph.providers.oauth`` +
``graph.providers.discovery`` that return JSON-safe dicts for the
``/api/config/oauth/*`` routes. After a sign-in completes or a provider is
disconnected, the agent graph is rebuilt in place (the same reload the setup wizard
uses) so the new credentials take effect without a restart.

All functions are sync and defensive — they translate the providers' typed errors into
``{ok/status, error}`` dicts so a route never 500s on a bad code or an expired flow.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("protopen.operator_api.oauth")


def _reload_agent() -> str:
    """Rebuild the graph in place after a credential change (never raises)."""
    from operator_api import config_setup

    # resolve_config_dir() (mkdir / os.access probe) runs OUTSIDE config_setup._reload_agent's
    # own handler, so guard the whole thing — a directory-resolution failure must not turn a
    # persisted-credentials OAuth route into a 500 after the token was already saved.
    try:
        return config_setup._reload_agent(config_setup.resolve_config_dir())
    except Exception as exc:  # noqa: BLE001 — reload is best-effort; files take effect next restart
        log.warning("agent reload after credential change failed: %s", exc)
        return f"reload deferred: {exc}"


def oauth_status() -> dict[str, Any]:
    """Read-only sign-in status for every native OAuth provider (safe to poll)."""
    try:
        from graph.providers.discovery import all_oauth_status

        return {"providers": all_oauth_status()}
    except Exception as exc:  # noqa: BLE001 — a status probe (store read, provider import) must never 500
        log.warning("oauth_status probe failed: %s", exc)
        return {"providers": [], "error": str(exc)}


def oauth_start(payload: dict[str, Any]) -> dict[str, Any]:
    """Begin a sign-in flow. Returns the device code / authorize URL + a flow_id."""
    from graph.providers.oauth_login import OAuthLoginError, login_start

    provider = ((payload or {}).get("provider") or "").strip()
    try:
        return {"ok": True, **login_start(provider)}
    except OAuthLoginError as exc:
        return {"ok": False, "error": str(exc), "provider": getattr(exc, "provider", provider)}
    except Exception as exc:  # noqa: BLE001 — an untyped transport/store failure returns structured, not 500
        return {"ok": False, "error": str(exc), "provider": provider}


def oauth_poll(payload: dict[str, Any]) -> dict[str, Any]:
    """Poll a device-code (openai-codex) flow. On completion, reload the agent."""
    from graph.providers.oauth_login import OAuthLoginError, codex_login_poll

    flow_id = ((payload or {}).get("flow_id") or "").strip()
    try:
        result = codex_login_poll(flow_id)
    except OAuthLoginError as exc:
        return {"status": "error", "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 — an untyped failure returns structured, not 500
        return {"status": "error", "error": str(exc)}
    if result.get("status") == "complete":
        result["reload"] = _reload_agent()
    return result


def oauth_complete(payload: dict[str, Any]) -> dict[str, Any]:
    """Complete a paste-the-code (anthropic-oauth) flow. On success, reload the agent."""
    from graph.providers.oauth_login import OAuthLoginError, anthropic_login_complete

    flow_id = ((payload or {}).get("flow_id") or "").strip()
    code = ((payload or {}).get("code") or "").strip()
    try:
        result = anthropic_login_complete(flow_id, code)
    except OAuthLoginError as exc:
        return {"status": "error", "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 — an untyped failure returns structured, not 500
        return {"status": "error", "error": str(exc)}
    if result.get("status") == "complete":
        result["reload"] = _reload_agent()
    return result


def oauth_cancel(payload: dict[str, Any]) -> dict[str, Any]:
    """Abandon an in-progress sign-in so its device/PKCE state can't be completed later."""
    from graph.providers.oauth_login import cancel_login

    return cancel_login(((payload or {}).get("flow_id") or "").strip())


def oauth_disconnect(payload: dict[str, Any]) -> dict[str, Any]:
    """Disconnect a provider: best-effort revoke + delete our token store + suppress
    auto-resolve until an in-console sign-in reconnects. Reloads the agent."""
    from graph.providers.oauth import OAuthCredentialError, disconnect

    provider = ((payload or {}).get("provider") or "").strip()
    try:
        result = disconnect(provider).as_dict()
    except OAuthCredentialError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 — an untyped store/revoke failure returns structured, not 500
        return {"ok": False, "error": str(exc)}
    result["ok"] = True
    result["reload"] = _reload_agent()
    return result
