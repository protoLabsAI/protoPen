"""Instance-scoped filesystem paths + atomic writes (ADR 0097).

protoPen persists operator config and credential stores in ONE writable directory that
survives an image re-pull and a SteamOS atomic update: ``/sandbox/config`` on the Deck,
``~/.protopen/config`` in local dev. ``operator_api.config_setup.resolve_config_dir``
resolves the same directory for the setup wizard's override + key file; this module is
the lower-level home the ``graph`` package can import without depending on ``operator_api``
(the native OAuth providers write their token stores here).
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class InstancePaths:
    """Resolved per-instance directories. Only ``config_dir`` is needed today."""

    config_dir: Path


def _resolve_config_dir() -> Path:
    """The writable dir for config + credential stores.

    Prefers ``/sandbox/config`` (the Deck's persistent mount); falls back to
    ``~/.protopen/config`` when ``/sandbox`` isn't writable (local dev) — the same
    probe ``operator_api.config_setup.resolve_config_dir`` uses, so both resolve to
    the same directory and the token stores sit beside the key file.
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


def instance_paths() -> InstancePaths:
    return InstancePaths(config_dir=_resolve_config_dir())


def atomic_write(path: Path, data: str, *, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` atomically with owner-only perms from creation.

    Writes to a temp file in the same directory (created 0600), fsync-free replace
    onto the target, so a reader never sees a half-written credential file and the
    perms are never briefly world-readable.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=f"-{path.name}")
    try:
        if hasattr(os, "fchmod"):  # POSIX — set perms before any content is written
            os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
        os.replace(tmp, path)
        os.chmod(path, mode)  # in case the target pre-existed with looser perms
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
