from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from operator_api.routes import register_operator_routes


class _Notes:
    def __init__(self) -> None:
        self.saved = None

    def load_workspace(self, project_path: str):
        return {"project_path": project_path}

    def save_workspace(self, project_path: str, workspace):
        self.saved = (project_path, workspace)


class _Beads:
    def status(self, project_path: str):
        return {"initialized": True, "project_path": project_path}

    def init(self, project_path: str, prefix=None):
        return {"initialized": True, "prefix": prefix}

    def list(self, project_path: str):
        return [{"id": "bd-1", "project_path": project_path}]

    def create(self, project_path: str, issue):
        return {"id": "bd-2", "title": issue["title"], "project_path": project_path}

    def update(self, project_path: str, issue_id: str, update):
        return {"id": issue_id, "status": update["status"], "project_path": project_path}

    def close(self, project_path: str, issue_id: str, reason=None):
        return {"id": issue_id, "status": "closed", "reason": reason}

    def delete(self, project_path: str, issue_id: str):
        return {"deleted": issue_id, "project_path": project_path}


def _client(*, run=None, api_key: str = "", engagement=None, knowledge=None, audit=None):
    app = FastAPI()
    notes = _Notes()

    async def default_run(req):
        return f"ran:{req['type']}:{req['prompt']}"

    async def batch(req):
        return f"batch:{len(req['tasks'])}"

    register_operator_routes(
        app,
        runtime_status=lambda: {"graph_loaded": True},
        subagent_list=lambda: [{"name": "threat_scanner"}],
        subagent_run=run or default_run,
        subagent_batch=batch,
        engagement_status=engagement,
        knowledge_search=knowledge,
        audit_recent=audit,
        notes_service=notes,
        beads_service=_Beads(),
        api_key=api_key,
    )
    return TestClient(app), notes


def test_operator_routes_return_expected_shapes(tmp_path) -> None:
    client, notes = _client()

    assert client.get("/api/runtime/status").json() == {"graph_loaded": True}
    assert client.get("/api/subagents").json() == {"subagents": [{"name": "threat_scanner"}]}

    run = client.post("/api/subagents/run", json={"type": "threat_scanner", "prompt": "check"})
    assert run.status_code == 200
    assert run.json()["output"] == "ran:threat_scanner:check"

    batch = client.post("/api/subagents/batch", json={"tasks": [{"prompt": "one"}, {"prompt": "two"}]})
    assert batch.json()["output"] == "batch:2"

    notes_path = str(tmp_path)
    assert client.get("/api/notes/workspace", params={"project_path": notes_path}).json() == {
        "workspace": {"project_path": notes_path},
    }
    save = client.post("/api/notes/workspace", json={"project_path": notes_path, "workspace": {"tabs": {}}})
    assert save.json() == {"ok": True}
    assert notes.saved == (notes_path, {"tabs": {}})

    assert client.get("/api/beads/status", params={"project_path": notes_path}).json() == {
        "initialized": True,
        "project_path": notes_path,
    }
    assert (
        client.post("/api/beads/issues", json={"project_path": notes_path, "title": "Task"}).json()["issue"]["id"]
        == "bd-2"
    )
    assert client.delete("/api/beads/issues/bd-1", params={"project_path": notes_path}).json() == {
        "deleted": "bd-1",
        "project_path": notes_path,
    }


def test_operator_routes_map_value_errors_to_400() -> None:
    async def run(_req):
        raise ValueError("bad prompt")

    client, _notes = _client(run=run)
    response = client.post("/api/subagents/run", json={"type": "threat_scanner", "prompt": "check"})

    assert response.status_code == 400
    assert response.json()["detail"] == "bad prompt"


def test_engagement_route_returns_status_when_wired() -> None:
    payload = {"active": True, "name": "op-1", "scope": "10.0.0.0/24", "total_findings": 2}
    client, _ = _client(engagement=lambda: payload)
    assert client.get("/api/engagement").json() == payload


def test_engagement_route_returns_inactive_shape_when_unwired() -> None:
    client, _ = _client()  # engagement_status omitted
    body = client.get("/api/engagement").json()
    assert body["active"] is False
    assert body["findings"] == []
    assert body["total_findings"] == 0


def test_knowledge_route_passes_query_filter_and_limit() -> None:
    seen = {}

    def knowledge(query, k, table):
        seen["args"] = (query, k, table)
        return {"query": query, "table": table, "count": 1, "hits": [{"table": "cves", "source_id": "CVE-1"}]}

    client, _ = _client(knowledge=knowledge)
    body = client.get("/api/knowledge/search", params={"q": "rce", "k": 5, "table": "cves"}).json()

    assert seen["args"] == ("rce", 5, "cves")
    assert body["count"] == 1
    assert body["hits"][0]["source_id"] == "CVE-1"


def test_knowledge_route_returns_empty_shape_when_unwired() -> None:
    client, _ = _client()  # knowledge_search omitted
    body = client.get("/api/knowledge/search", params={"q": "anything"}).json()
    assert body == {"query": "anything", "table": None, "count": 0, "hits": []}


def test_audit_route_passes_limit_and_session() -> None:
    seen = {}

    def audit(n, session_id):
        seen["args"] = (n, session_id)
        return {"count": 1, "entries": [{"tool": "nmap", "success": True}], "summary": {"total": 1}}

    client, _ = _client(audit=audit)
    body = client.get("/api/audit/recent", params={"n": 25, "session_id": "s1"}).json()

    assert seen["args"] == (25, "s1")
    assert body["count"] == 1
    assert body["entries"][0]["tool"] == "nmap"


def test_audit_route_returns_empty_shape_when_unwired() -> None:
    client, _ = _client()  # audit_recent omitted
    body = client.get("/api/audit/recent").json()
    assert body == {"count": 0, "entries": [], "summary": {"total": 0, "successes": 0, "failures": 0}}


def test_operator_routes_enforce_api_key() -> None:
    client, _ = _client(api_key="secret-key")

    assert client.get("/api/runtime/status").status_code == 401
    assert client.get("/api/runtime/status", headers={"x-api-key": "wrong"}).status_code == 401

    ok = client.get("/api/runtime/status", headers={"x-api-key": "secret-key"})
    assert ok.status_code == 200
    assert ok.json() == {"graph_loaded": True}


def test_operator_routes_open_when_no_api_key() -> None:
    client, _ = _client()  # api_key="" → unauthenticated
    assert client.get("/api/runtime/status").status_code == 200
