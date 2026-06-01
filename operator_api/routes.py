"""FastAPI route registration for the React operator console contracts."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from operator_api.beads import BeadsCommandError, BeadsService
from operator_api.notes import NotesService


class SubagentRunRequest(BaseModel):
    session_id: str = "manual-subagent"
    type: str = "researcher"
    description: str = ""
    prompt: str
    emit_skill: bool = False


class SubagentBatchRequest(BaseModel):
    session_id: str = "manual-subagent"
    tasks: list[dict[str, Any]]


class ScheduleAddRequest(BaseModel):
    prompt: str
    schedule: str  # 5-field cron or ISO-8601 datetime
    job_id: str | None = None


class NotesSaveRequest(BaseModel):
    project_path: str
    workspace: dict[str, Any]


class BeadsInitRequest(BaseModel):
    project_path: str
    prefix: str | None = None


class BeadsCreateRequest(BaseModel):
    project_path: str
    title: str
    type: str = "task"
    priority: int = 2
    description: str | None = None
    assignee: str | None = None


class BeadsUpdateRequest(BaseModel):
    project_path: str
    title: str | None = None
    description: str | None = None
    status: str | None = None
    priority: int | None = None
    type: str | None = None
    assignee: str | None = None


class BeadsCloseRequest(BaseModel):
    project_path: str
    reason: str | None = None


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "not loaded" in str(exc).lower():
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, BeadsCommandError):
        return HTTPException(status_code=500, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))


def _model_payload(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def register_operator_routes(
    app,
    *,
    runtime_status: Callable[[], dict[str, Any]],
    subagent_list: Callable[[], list[dict[str, Any]]],
    subagent_run: Callable[[dict[str, Any]], Awaitable[str]],
    subagent_batch: Callable[[dict[str, Any]], Awaitable[str]],
    engagement_status: Callable[[], dict[str, Any]] | None = None,
    engagement_report: Callable[[], dict[str, Any]] | None = None,
    engagement_report_generate: Callable[[], dict[str, Any]] | None = None,
    knowledge_search: Callable[[str, int, str | None], dict[str, Any]] | None = None,
    skills_list: Callable[[str], dict[str, Any]] | None = None,
    targets_list: Callable[[str, str, int], dict[str, Any]] | None = None,
    target_get: Callable[[int], dict[str, Any]] | None = None,
    engagements_list: Callable[[], dict[str, Any]] | None = None,
    intel_search: Callable[[str, int], dict[str, Any]] | None = None,
    audit_recent: Callable[[int, str | None], dict[str, Any]] | None = None,
    agent_launch: Callable[[dict[str, Any]], str] | None = None,
    agent_list: Callable[[], list[dict[str, Any]]] | None = None,
    agent_get: Callable[[str], dict[str, Any] | None] | None = None,
    agent_cancel: Callable[[str], bool] | None = None,
    scheduler_list: Callable[[], dict[str, Any]] | None = None,
    scheduler_add: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    scheduler_cancel: Callable[[str], dict[str, Any]] | None = None,
    beads_service: BeadsService | None = None,
    notes_service: NotesService | None = None,
    chat_commands: Callable[[], dict[str, Any]] | None = None,
    api_key: str = "",
) -> None:
    """Register React operator-console routes on a FastAPI app.

    When ``api_key`` is non-empty, every operator route requires a matching
    ``x-api-key`` header — the same key protoPen's A2A surface authenticates
    with. The React console stores the key and sends it on every request;
    a 401 drives its login gate.
    """
    beads = beads_service or BeadsService()
    notes = notes_service or NotesService()

    auth_deps: list[Any] = []
    if api_key:

        async def _require_operator_key(x_api_key: str = Header(default="")) -> None:
            if x_api_key != api_key:
                raise HTTPException(status_code=401, detail="Unauthorized")

        auth_deps = [Depends(_require_operator_key)]

    router = APIRouter(dependencies=auth_deps)

    @router.get("/api/runtime/status", summary="Runtime status")
    async def _runtime_status():
        return runtime_status()

    @router.get("/api/chat/commands", summary="List chat slash-commands")
    async def _chat_commands():
        return chat_commands() if chat_commands else {"commands": []}

    @router.get("/api/subagents", summary="List subagents")
    async def _subagents():
        return {"subagents": subagent_list()}

    @router.get("/api/engagement", summary="Engagement snapshot")
    async def _engagement():
        if engagement_status is None:
            return {
                "active": False,
                "name": "",
                "scope": "",
                "mode": "",
                "phase": "",
                "started_at": "",
                "finding_counts": {},
                "total_findings": 0,
                "findings": [],
            }
        return engagement_status()

    @router.get("/api/engagement/report", summary="Read engagement report")
    async def _engagement_report():
        if engagement_report is None:
            return {"available": False, "name": "", "path": "", "markdown": ""}
        try:
            return await asyncio.to_thread(engagement_report)
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.post("/api/engagement/report", summary="Generate engagement report")
    async def _engagement_report_generate():
        if engagement_report_generate is None:
            raise HTTPException(status_code=409, detail="report generation is not available")
        try:
            return await asyncio.to_thread(engagement_report_generate)
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.get("/api/knowledge/search", summary="Search the knowledge store")
    async def _knowledge_search(q: str, k: int = 10, table: str | None = None):
        if knowledge_search is None:
            return {"query": q, "table": table, "count": 0, "hits": []}
        try:
            return await asyncio.to_thread(knowledge_search, q, k, table)
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.get("/api/skills", summary="List/search learned skills")
    async def _skills_list(q: str = ""):
        if skills_list is None:
            return {"enabled": False, "count": 0, "skills": []}
        try:
            return await asyncio.to_thread(skills_list, q)
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.get("/api/targets", summary="List discovered targets")
    async def _targets_list(q: str = "", device_type: str = "", limit: int = 50):
        if targets_list is None:
            return {"query": q, "count": 0, "targets": []}
        try:
            return await asyncio.to_thread(targets_list, q, device_type, limit)
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.get("/api/targets/{host_id}", summary="Target profile")
    async def _target_get(host_id: int):
        if target_get is None:
            raise HTTPException(status_code=409, detail="target store is not available")
        try:
            return await asyncio.to_thread(target_get, host_id)
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.get("/api/engagements", summary="Engagement history")
    async def _engagements_list():
        if engagements_list is None:
            return {"count": 0, "engagements": []}
        try:
            return await asyncio.to_thread(engagements_list)
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.get("/api/intel/search", summary="Unified intel search")
    async def _intel_search(q: str, k: int = 20):
        if intel_search is None:
            return {"query": q, "count": 0, "hits": []}
        try:
            return await asyncio.to_thread(intel_search, q, k)
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.get("/api/audit/recent", summary="Recent audit entries")
    async def _audit_recent(n: int = 50, session_id: str | None = None):
        if audit_recent is None:
            return {"count": 0, "entries": [], "summary": {"total": 0, "successes": 0, "failures": 0}}
        try:
            return await asyncio.to_thread(audit_recent, n, session_id)
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.post("/api/subagents/run", summary="Run a subagent")
    async def _subagent_run(req: SubagentRunRequest):
        try:
            output = await subagent_run(_model_payload(req))
            return {"ok": True, "session_id": req.session_id, "output": output}
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.post("/api/subagents/batch", summary="Run subagents concurrently")
    async def _subagent_batch(req: SubagentBatchRequest):
        try:
            output = await subagent_batch(_model_payload(req))
            return {"ok": True, "session_id": req.session_id, "output": output}
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.post("/api/agents/launch", summary="Launch a tracked agent")
    async def _agent_launch(req: SubagentRunRequest):
        if agent_launch is None:
            raise HTTPException(status_code=409, detail="agent launching is not available")
        try:
            # Synchronous: registry.launch must schedule the task on this loop.
            return {"task_id": agent_launch(_model_payload(req))}
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.get("/api/agents", summary="List agent runs")
    async def _agents_list():
        return {"agents": agent_list() if agent_list else []}

    @router.get("/api/agents/{task_id}", summary="Get an agent run")
    async def _agent_get(task_id: str):
        run = agent_get(task_id) if agent_get else None
        if run is None:
            raise HTTPException(status_code=404, detail="agent run not found")
        return run

    @router.post("/api/agents/{task_id}/cancel", summary="Cancel an agent run")
    async def _agent_cancel(task_id: str):
        return {"cancelled": bool(agent_cancel(task_id)) if agent_cancel else False}

    @router.get("/api/scheduler/jobs", summary="List scheduled jobs")
    async def _scheduler_jobs():
        if scheduler_list is None:
            return {"jobs": [], "backend": "disabled"}
        try:
            return await asyncio.to_thread(scheduler_list)
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.post("/api/scheduler/jobs", summary="Schedule a job")
    async def _scheduler_add(req: ScheduleAddRequest):
        if scheduler_add is None:
            raise HTTPException(status_code=409, detail="scheduler is not available")
        try:
            return {"job": await asyncio.to_thread(scheduler_add, _model_payload(req))}
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.delete("/api/scheduler/jobs/{job_id}", summary="Cancel a scheduled job")
    async def _scheduler_cancel(job_id: str):
        if scheduler_cancel is None:
            raise HTTPException(status_code=409, detail="scheduler is not available")
        try:
            return await asyncio.to_thread(scheduler_cancel, job_id)
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.get("/api/notes/workspace", summary="Load notes workspace")
    async def _notes_get(project_path: str):
        try:
            workspace = await asyncio.to_thread(notes.load_workspace, project_path)
            return {"workspace": workspace}
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.post("/api/notes/workspace", summary="Save notes workspace")
    async def _notes_save(req: NotesSaveRequest):
        try:
            await asyncio.to_thread(notes.save_workspace, req.project_path, req.workspace)
            return {"ok": True}
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.get("/api/beads/status", summary="Beads status")
    async def _beads_status(project_path: str):
        try:
            return await asyncio.to_thread(beads.status, project_path)
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.post("/api/beads/init", summary="Initialize beads")
    async def _beads_init(req: BeadsInitRequest):
        try:
            return await asyncio.to_thread(beads.init, req.project_path, req.prefix)
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.get("/api/beads/issues", summary="List beads issues")
    async def _beads_list(project_path: str):
        try:
            issues = await asyncio.to_thread(beads.list, project_path)
            return {"issues": issues}
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.post("/api/beads/issues", summary="Create a beads issue")
    async def _beads_create(req: BeadsCreateRequest):
        try:
            issue = await asyncio.to_thread(beads.create, req.project_path, _model_payload(req))
            return {"issue": issue}
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.patch("/api/beads/issues/{issue_id}", summary="Update a beads issue")
    async def _beads_update(issue_id: str, req: BeadsUpdateRequest):
        try:
            issue = await asyncio.to_thread(beads.update, req.project_path, issue_id, _model_payload(req))
            return {"issue": issue}
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.post("/api/beads/issues/{issue_id}/close", summary="Close a beads issue")
    async def _beads_close(issue_id: str, req: BeadsCloseRequest):
        try:
            issue = await asyncio.to_thread(beads.close, req.project_path, issue_id, req.reason)
            return {"issue": issue}
        except Exception as exc:
            raise _http_error(exc) from exc

    @router.delete("/api/beads/issues/{issue_id}", summary="Delete a beads issue")
    async def _beads_delete(issue_id: str, project_path: str):
        try:
            return await asyncio.to_thread(beads.delete, project_path, issue_id)
        except Exception as exc:
            raise _http_error(exc) from exc

    app.include_router(router)
