"""Agent + runtime init/builders (ADR 0023 phase 2b).

The boot-time builders that stand up the LangGraph runtime: the durable
checkpointer (+ its prune loop), the skills index, the workflow registry, and
the agent graph itself, plus the vLLM model probe. Extracted verbatim from
``server/__init__.py`` — same lifecycle, zero functional change.

Everything writes through ``runtime.state.STATE`` (no module globals) and reads
the knowledge store via ``runtime.state.get_store``, so this module needs nothing
from ``server`` — no import cycle. ``build_app`` calls ``_init_langgraph_agent()``
at boot and schedules ``_checkpoint_prune_loop()`` on startup.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from runtime.state import STATE, get_store

# Repo root — bundled config / workflows live here. This module sits at
# ``server/agent_init.py``, so the root is one directory up (``parents[1]``).
_REPO_ROOT = Path(__file__).resolve().parents[1]


def _resolve_checkpoint_db(configured: str) -> str:
    """Pick a writable checkpoint DB path; fall back to ~/.protopen when the
    configured dir (default /sandbox) isn't creatable (e.g. local dev)."""
    import os

    candidate = Path(configured).expanduser()
    try:
        candidate.parent.mkdir(parents=True, exist_ok=True)
        if os.access(candidate.parent, os.W_OK):
            return str(candidate)
    except OSError:
        pass
    fallback = Path.home() / ".protopen" / "sessions.db"
    fallback.parent.mkdir(parents=True, exist_ok=True)
    return str(fallback)


def _build_checkpointer(configured_db: str):
    """Durable SQLite checkpointer (chat history survives restarts), falling back
    to an in-memory saver if SQLite init fails so a bad path never blocks boot.

    The graph compiles synchronously at boot, before the event loop, so we use a
    wrapped sync saver (graph/checkpointer.py) rather than the loop-bound
    AsyncSqliteSaver. Bound into the graph at compile time by the caller.
    """
    try:
        from graph.checkpointer import build_sqlite_checkpointer

        path = _resolve_checkpoint_db(configured_db)
        saver = build_sqlite_checkpointer(path)
        STATE.checkpoint_path = path  # the pruner sweeps this file
        print(f"[sessions] Persistent checkpointer: {path}")
        return saver
    except Exception as exc:
        from langgraph.checkpoint.memory import MemorySaver

        print(f"[sessions] SQLite checkpointer init failed ({exc}); using in-memory (history won't persist)")
        return MemorySaver()


async def _checkpoint_prune_loop() -> None:
    """Periodically trim the SQLite checkpoint DB (per-thread cap + age TTL).

    Reads the path + knobs from the live globals each pass so a config reload
    takes effect without restarting the loop. Failures are logged, never fatal.
    """
    from graph.checkpoint_prune import prune_checkpoints

    await asyncio.sleep(60)  # let boot settle before the first sweep
    while True:
        cfg = STATE.graph_config
        path = STATE.checkpoint_path
        interval_h = getattr(cfg, "checkpoint_prune_interval_hours", 0) if cfg else 0
        if path and cfg and interval_h > 0:
            try:
                # > 0 only: a negative max_age_days would invert the cutoff and
                # delete every thread. 0 / negative → no age TTL (cap-only sweep).
                max_age = cfg.checkpoint_max_age_days * 86400 if cfg.checkpoint_max_age_days > 0 else None
                res = await asyncio.to_thread(
                    prune_checkpoints,
                    path,
                    keep_per_thread=cfg.checkpoint_keep_per_thread,
                    max_age_seconds=max_age,
                )
                if res["threads_deleted"] or res["checkpoints_deleted"]:
                    print(
                        f"[checkpoint-prune] removed {res['threads_deleted']} idle thread(s), "
                        f"{res['checkpoints_deleted']} old checkpoint(s)"
                    )
            except Exception as exc:
                print(f"[checkpoint-prune] sweep failed: {exc}")
        await asyncio.sleep(max(1, interval_h) * 3600)


def _build_skills_index(config):
    """Build the SKILL.md skill index and seed it from disk (bundled config/skills/
    + a writable dir). Best-effort; never blocks boot."""
    if not getattr(config, "skills_enabled", True):
        return None
    try:
        import os

        from graph.skills import SkillsIndex, seed_index

        db = Path(getattr(config, "skills_db_path", "") or "/sandbox/skills.db").expanduser()
        try:
            db.parent.mkdir(parents=True, exist_ok=True)
            if not os.access(db.parent, os.W_OK):
                raise OSError
        except OSError:
            db = Path.home() / ".protopen" / "skills.db"
            db.parent.mkdir(parents=True, exist_ok=True)
        index = SkillsIndex(str(db))

        dirs: list[str] = []
        bundled = _REPO_ROOT / "config" / "skills"
        if bundled.is_dir():
            dirs.append(str(bundled))
        live = Path(getattr(config, "skills_dir", "") or "/sandbox/skills").expanduser()
        try:
            live.mkdir(parents=True, exist_ok=True)
            dirs.append(str(live))
        except OSError:
            pass
        n = seed_index(index, dirs)
        print(f"[skills] index ready at {db} ({n} skill(s) loaded)")
        return index
    except Exception as exc:
        print(f"[skills] index init failed ({exc}); skills disabled")
        return None


def _build_workflow_registry(config):
    """Load workflow recipes (ADR 0002) from the bundled repo workflows/ dir plus
    a writable dir (user/agent-emitted). Best-effort; never blocks boot."""
    if not getattr(config, "workflows_enabled", True):
        return None
    try:
        import os

        from graph.workflows.registry import WorkflowRegistry

        dirs: list[str] = []
        bundled = _REPO_ROOT / "workflows"
        if bundled.is_dir():
            dirs.append(str(bundled))
        writable = Path(getattr(config, "workflow_dir", "") or "/sandbox/workflows").expanduser()
        try:
            writable.mkdir(parents=True, exist_ok=True)
            if not os.access(writable, os.W_OK):
                raise OSError
        except OSError:
            writable = Path.home() / ".protopen" / "workflows"
            writable.mkdir(parents=True, exist_ok=True)
        dirs.append(str(writable))
        return WorkflowRegistry(dirs, writable_dir=str(writable))
    except Exception as exc:
        print(f"[workflows] registry init failed ({exc}); workflows disabled")
        return None


def _init_langgraph_agent():
    """Initialize the LangGraph agent backend."""

    from graph.agent import create_researcher_graph
    from graph.config import LangGraphConfig
    from sitrep import run_sitrep

    # Load the persistent config override (written by the setup wizard; lives on
    # the /sandbox mount so it survives image upgrades + OS updates) in preference
    # to the bundled file. Then promote a local BYO key into OPENAI_API_KEY BEFORE
    # the graph (and guardrails) build — an env/Infisical key always wins.
    from operator_api import config_setup as _config_setup

    _config_dir = _config_setup.resolve_config_dir()
    _override = _config_setup.config_override_path(_config_dir)
    config_path = _override if _override.exists() else (_REPO_ROOT / "config" / "langgraph-config.yaml")
    STATE.graph_config = LangGraphConfig.from_yaml(config_path)
    _config_setup.load_local_key_into_env(_config_dir, STATE.graph_config.api_base)

    store = get_store()

    # Persistent session checkpointer — bound into the graph at COMPILE time
    # below. A checkpointer set only in the invoke config is ignored by
    # LangGraph, which gave the chat amnesia (every turn started fresh).
    STATE.checkpointer = _build_checkpointer("/sandbox/knowledge/sessions.db")
    STATE.workflow_registry = _build_workflow_registry(STATE.graph_config)
    STATE.skills_index = _build_skills_index(STATE.graph_config)

    # Run startup sitrep — hardware, network, engagement status
    engagement_config = _REPO_ROOT / "config" / "engagement-config.json"
    status_block = run_sitrep(engagement_config)
    if status_block:
        print("[sitrep] Startup probe injected into system prompt")

    STATE.graph = create_researcher_graph(
        config=STATE.graph_config,
        knowledge_store=store,
        include_subagents=True,
        sitrep=status_block,
        checkpointer=STATE.checkpointer,
        workflow_registry=STATE.workflow_registry,
        skills_index=STATE.skills_index,
    )

    print(f"[researcher] LangGraph agent initialized (model: {STATE.graph_config.model_name})")


def _detect_vllm_model(api_base: str) -> str | None:
    """Query vLLM /v1/models to get the currently loaded model."""
    import httpx

    try:
        resp = httpx.get(f"{api_base}/models", timeout=5)
        data = resp.json().get("data", [])
        if data:
            return data[0]["id"]
    except Exception:
        pass
    return None
