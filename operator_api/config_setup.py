"""Setup-wizard backend — the ``/api/config/*`` endpoints the React wizard calls.

The frontend ``apps/web/src/setup/SetupWizard.tsx`` is a complete 7-step wizard
gated on ``runtime.setup_complete``; this module supplies the endpoints it needs
so a new operator can enter their OWN OpenAI-compatible base/key/model in-browser
instead of depending on a fleet Infisical token.

Persistence is the load-bearing constraint: on the Steam Deck the runtime is a
podman container that mounts host ``~/.local/share/protopen-rt-data`` → ``/sandbox``.
Anything under ``/sandbox`` survives a container image re-pull AND a SteamOS atomic
update; anything baked into the image (e.g. the repo's ``config/langgraph-config.yaml``)
does not. So the wizard writes:

  * ``<config_dir>/langgraph-config.yaml`` (644) — a config override, loaded in
    preference to the bundled file by ``server/agent_init.py``.
  * ``<config_dir>/openai_api_key`` (600) — the raw key, never written into the yaml.
  * ``<workspace>/SOUL.md`` — picked up first by ``graph/prompts.py:_read_soul``.

where ``config_dir`` is ``/sandbox/config`` (Deck) with a ``~/.protopen/config``
fallback for local dev — the same writability probe ``agent_init.py`` already uses.

An env/Infisical ``OPENAI_API_KEY`` always wins over the local key file, so the
fleet path is unchanged (those Decks never show the wizard).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

# operator_api/ → repo root (config/SOUL.md, config/langgraph-config.yaml live here).
_REPO_ROOT = Path(__file__).resolve().parents[1]
_BUNDLED_CONFIG = _REPO_ROOT / "config" / "langgraph-config.yaml"
_BUNDLED_SOUL = _REPO_ROOT / "config" / "SOUL.md"
_PERSONAS_DIR = _REPO_ROOT / "config" / "personas"

_KEY_FILENAME = "openai_api_key"
_CONFIG_FILENAME = "langgraph-config.yaml"


# ── persistence helpers ──────────────────────────────────────────────────────


def resolve_config_dir() -> Path:
    """Writable dir for the config override + key file.

    Prefers ``/sandbox/config`` (the Deck's persistent mount); falls back to
    ``~/.protopen/config`` when ``/sandbox`` isn't writable (local dev) — same
    probe pattern as ``server/agent_init.py``.
    """
    candidate = Path("/sandbox/config")
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        if os.access(candidate, os.W_OK):
            return candidate
    except OSError:
        pass
    fallback = Path.home() / ".protopen" / "config"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def config_override_path(config_dir: Path | None = None) -> Path:
    return (config_dir or resolve_config_dir()) / _CONFIG_FILENAME


def key_file_path(config_dir: Path | None = None) -> Path:
    return (config_dir or resolve_config_dir()) / _KEY_FILENAME


def load_local_key_into_env(config_dir: Path | None = None, api_base: str = "") -> bool:
    """Promote the local key file into ``OPENAI_API_KEY`` for the agent.

    No-ops when an env key is already present (env/Infisical wins). Returns True
    when the local key was applied. Must run before ``guardrails`` is first
    imported so its module-level key/base reads see the value (boot path does this
    in ``agent_init`` before ``create_researcher_graph``).
    """
    if os.environ.get("OPENAI_API_KEY"):
        return False
    kf = key_file_path(config_dir)
    try:
        key = kf.read_text(encoding="utf-8").strip()
    except OSError:
        return False
    if not key:
        return False
    os.environ["OPENAI_API_KEY"] = key
    if api_base:
        os.environ.setdefault("OPENAI_BASE_URL", api_base)
    return True


def is_setup_complete(config_dir: Path | None = None, graph_config: Any = None) -> bool:
    """Whether a usable LLM key is configured by ANY path (env, local file, config).

    The local-file check requires non-empty *content*, not mere existence —
    matching ``load_local_key_into_env`` — so an empty/unreadable key file can't
    mark setup complete and hide the wizard while the agent still has no key.
    """
    if os.environ.get("OPENAI_API_KEY"):
        return True
    try:
        if key_file_path(config_dir).read_text(encoding="utf-8").strip():
            return True
    except OSError:
        pass
    if graph_config is None:
        from runtime.state import STATE

        graph_config = STATE.graph_config
    return bool(getattr(graph_config, "api_key", "") if graph_config is not None else "")


def _write_key(path: Path, key: str) -> None:
    """Write the key with 0600 from creation (don't briefly expose it world-readable)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, 0o600)  # in case the file pre-existed with looser perms


# ── SOUL presets ─────────────────────────────────────────────────────────────


def list_presets() -> list[str]:
    """Available SOUL presets. Always includes the bundled ``SOUL`` if present;
    extra personas can be dropped in ``config/personas/*.md`` later."""
    presets: list[str] = []
    if _BUNDLED_SOUL.exists():
        presets.append("SOUL")
    if _PERSONAS_DIR.is_dir():
        presets += sorted(p.stem for p in _PERSONAS_DIR.glob("*.md"))
    return presets or ["SOUL"]


def _preset_path(name: str) -> Path:
    """Resolve a preset name to a file, guarding against path traversal (same
    ``relative_to`` guard style as ``operator_api/web.py``)."""
    name = (name or "").strip()
    if name == "SOUL":
        return _BUNDLED_SOUL
    candidate = (_PERSONAS_DIR / f"{name}.md").resolve()
    try:
        candidate.relative_to(_PERSONAS_DIR.resolve())
    except ValueError as exc:
        raise ValueError("invalid preset name") from exc
    return candidate


def get_preset(name: str) -> dict[str, Any]:
    path = _preset_path(name)
    if not path.is_file():
        raise FileNotFoundError(f"preset not found: {name}")
    return {"name": name, "content": path.read_text(encoding="utf-8")}


def _read_active_soul(config_dir: Path | None = None) -> str:
    """The SOUL the agent would use: workspace copy first, then bundled (mirrors
    ``graph/prompts.py:_read_soul``)."""
    cdir = config_dir or resolve_config_dir()
    for candidate in (cdir.parent / "SOUL.md", _BUNDLED_SOUL):
        try:
            text = candidate.read_text(encoding="utf-8")
        except OSError:
            continue
        if text:
            return text
    return ""


# ── endpoints ────────────────────────────────────────────────────────────────


def setup_status() -> dict[str, Any]:
    """GET /api/config/setup-status → {setup_complete, presets}."""
    return {"setup_complete": is_setup_complete(), "presets": list_presets()}


def get_config() -> dict[str, Any]:
    """GET /api/config → {config: <nested AgentConfig>, soul}.

    Builds the wizard's nested shape from the flat live ``LangGraphConfig``. Never
    returns the api_key (the wizard's key field placeholder is "leave blank to
    preserve"). The ``researcher`` subagent is a wizard-only concept with no
    protoPen backend home, so it's a display default.
    """
    from runtime.state import STATE

    cfg = STATE.graph_config
    nested = {
        "model": {
            "provider": getattr(cfg, "model_provider", "openai"),
            "name": getattr(cfg, "model_name", ""),
            "api_base": getattr(cfg, "api_base", ""),
            "temperature": getattr(cfg, "temperature", 0.3),
            "max_tokens": getattr(cfg, "max_tokens", 4096),
            "max_iterations": getattr(cfg, "max_iterations", 75),
        },
        "subagents": {"researcher": {"enabled": True, "tools": [], "max_turns": 40}},
        "middleware": {
            "knowledge": bool(getattr(cfg, "knowledge_middleware", True)),
            "audit": bool(getattr(cfg, "audit_middleware", True)),
            "memory": bool(getattr(cfg, "memory_middleware", True)),
            "scheduler": True,
        },
        "knowledge": {
            "db_path": getattr(cfg, "knowledge_db_path", ""),
            "embed_model": getattr(cfg, "embed_model", ""),
            "top_k": getattr(cfg, "knowledge_top_k", 10),
        },
        "identity": {
            "name": getattr(cfg, "identity_name", "protopen") or "protopen",
            "operator": getattr(cfg, "identity_operator", "") or "",
        },
        "auth": {"token": ""},
        "runtime": {"autostart_on_boot": True},
    }
    return {"config": nested, "soul": _read_active_soul()}


def probe_models(api_base: str, api_key: str = "") -> dict[str, Any]:
    """POST /api/config/models → {models, error}.

    Lists models from an arbitrary OpenAI-compatible ``{api_base}/models``. Always
    returns HTTP 200 with an ``error`` string on failure so the wizard surfaces it
    inline. Mirrors ``server/agent_init.py:_detect_vllm_model``.
    """
    import httpx

    base = (api_base or "").rstrip("/")
    if not base:
        return {"models": [], "error": "api_base is required"}
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        resp = httpx.get(f"{base}/models", headers=headers, timeout=8)
        resp.raise_for_status()
        data = resp.json().get("data", [])
        models = [d["id"] for d in data if isinstance(d, dict) and d.get("id")]
        return {"models": models, "error": ""}
    except Exception as exc:  # noqa: BLE001 — surfaced to the operator, not fatal
        return {"models": [], "error": str(exc)}


def run_setup(payload: dict[str, Any]) -> dict[str, Any]:
    """POST /api/config/setup → {ok, message}.

    Writes the config override (merged onto the bundled/existing yaml so nothing
    the wizard doesn't model is lost), the key file (600, only when provided), and
    SOUL, then rebuilds the agent graph in-process. Files are persisted before the
    rebuild, so a rebuild failure still reports ``ok`` with a "restart to apply"
    message — the next start reads the override regardless.
    """
    nested = (payload or {}).get("config") or {}
    cfg_dir = resolve_config_dir()
    override = config_override_path(cfg_dir)

    # Base doc = existing override else the bundled config, so we preserve every
    # block the wizard doesn't touch (extra subagents, routing, compaction, …).
    base_path = override if override.exists() else _BUNDLED_CONFIG
    try:
        doc = yaml.safe_load(base_path.read_text(encoding="utf-8")) or {} if base_path.exists() else {}
    except (OSError, yaml.YAMLError):
        doc = {}
    if not isinstance(doc, dict):
        doc = {}

    model = nested.get("model") or {}
    doc.setdefault("model", {})
    for k in ("provider", "name", "api_base", "temperature", "max_tokens", "max_iterations"):
        if model.get(k) is not None:
            doc["model"][k] = model[k]
    doc["model"]["api_key"] = ""  # the secret lives only in the key file

    middleware = nested.get("middleware") or {}
    doc.setdefault("middleware", {})
    for k in ("knowledge", "audit", "memory"):
        if k in middleware:
            doc["middleware"][k] = bool(middleware[k])

    knowledge = nested.get("knowledge") or {}
    doc.setdefault("knowledge", {})
    for k in ("db_path", "embed_model", "top_k"):
        if knowledge.get(k) is not None:
            doc["knowledge"][k] = knowledge[k]

    identity = nested.get("identity") or {}
    doc["identity"] = {
        "name": (identity.get("name") or "protopen"),
        "operator": identity.get("operator") or "",
    }

    try:
        cfg_dir.mkdir(parents=True, exist_ok=True)
        override.write_text(yaml.safe_dump(doc, sort_keys=False, default_flow_style=False), encoding="utf-8")
        api_key = (model.get("api_key") or "").strip()
        if api_key:
            _write_key(key_file_path(cfg_dir), api_key)
        soul = (payload or {}).get("soul") or ""
        if soul.strip():
            soul_path = cfg_dir.parent / "SOUL.md"
            soul_path.parent.mkdir(parents=True, exist_ok=True)
            soul_path.write_text(soul, encoding="utf-8")
    except OSError as exc:
        return {"ok": False, "message": f"Could not write config: {exc}"}

    return {"ok": True, "message": _reload_agent(cfg_dir)}


def _reload_agent(config_dir: Path) -> str:
    """Re-read the override and rebuild the graph in place (reuses the
    ``switch_provider`` rebuild). Never raises — on failure the persisted files
    take effect on the next restart."""
    try:
        from graph.agent import create_researcher_graph
        from graph.config import LangGraphConfig
        from runtime.state import STATE, get_store

        STATE.graph_config = LangGraphConfig.from_yaml(config_override_path(config_dir))
        load_local_key_into_env(config_dir, STATE.graph_config.api_base)
        STATE.graph = create_researcher_graph(
            config=STATE.graph_config,
            knowledge_store=get_store(),
            include_subagents=True,
            checkpointer=STATE.checkpointer,
            workflow_registry=STATE.workflow_registry,
            skills_index=STATE.skills_index,
        )
        return "Setup saved — agent reloaded."
    except Exception as exc:  # noqa: BLE001 — files persisted; restart applies them
        return f"Setup saved. Restart pwnDeck to apply ({exc})."
