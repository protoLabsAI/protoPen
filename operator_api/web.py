"""Static serving helpers for the React operator console."""

from __future__ import annotations

from pathlib import Path

from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# The SPA entry (index.html) points at content-hashed asset bundles, so it must
# never be served stale — a cached index.html pins the browser to an old build
# after a deploy. `no-cache` = "always revalidate" (cheap 304 when unchanged),
# not "don't store". The hashed bundles under /app/assets are immutable by
# filename and stay cacheable via the StaticFiles mount.
_NO_CACHE = {"Cache-Control": "no-cache"}


def mount_react_app(app, dist_dir: str | Path, *, app_path: str = "/app") -> bool:
    """Mount a built Vite app under ``app_path`` when dist assets exist.

    Returns False when the build output is absent so local Gradio-only dev
    remains unchanged until ``npm run web:build`` has produced the React app.
    """
    dist = Path(dist_dir).resolve()
    index_path = dist / "index.html"
    if not index_path.exists():
        return False

    app_path = "/" + app_path.strip("/")
    assets_dir = dist / "assets"
    if assets_dir.exists():
        app.mount(
            f"{app_path}/assets",
            StaticFiles(directory=str(assets_dir)),
            name="operator_assets",
        )

    @app.get(app_path, include_in_schema=False)
    async def _operator_index() -> FileResponse:
        return FileResponse(str(index_path), headers=_NO_CACHE)

    @app.get(f"{app_path}/{{path:path}}", include_in_schema=False)
    async def _operator_fallback(path: str) -> FileResponse:
        candidate = (dist / path).resolve()
        try:
            candidate.relative_to(dist)
        except ValueError:
            candidate = index_path
        # Non-hashed files (favicon, manifest) and the SPA index fallback are
        # served revalidate-always; the content-hashed bundles are served by the
        # StaticFiles mount above and never reach this handler.
        if candidate.is_file():
            return FileResponse(str(candidate), headers=_NO_CACHE)
        return FileResponse(str(index_path), headers=_NO_CACHE)

    return True
