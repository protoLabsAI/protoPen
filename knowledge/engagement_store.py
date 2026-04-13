"""Persistent SQLite audit trail for engagement operations."""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = "/sandbox/knowledge/engagements.db"
_SCHEMA_PATH = Path(__file__).parent / "engagement_schema.sql"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EngagementStore:
    """SQLite-backed persistent store for engagement audit trails."""

    def __init__(self, db_path: str = _DEFAULT_DB_PATH):
        self._db_path = db_path
        self._db: Optional[sqlite3.Connection] = None

    def _get_db(self) -> sqlite3.Connection:
        if self._db is not None:
            return self._db
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self._db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        schema_sql = _SCHEMA_PATH.read_text()
        self._db.executescript(schema_sql)
        return self._db

    # ── Engagements ──────────────────────────────────────────────────────

    def create_engagement(
        self, name: str, scope_json: str = "{}", mode: str = "PASSIVE", max_phase: str = None,
    ) -> int:
        db = self._get_db()
        cur = db.execute(
            "INSERT INTO engagements (name, scope_json, mode, max_phase, started_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, scope_json, mode, max_phase, _now()),
        )
        db.commit()
        return cur.lastrowid

    def end_engagement(self, engagement_id: int, outcome: str = "") -> None:
        db = self._get_db()
        db.execute(
            "UPDATE engagements SET ended_at = ?, outcome = ? WHERE id = ?",
            (_now(), outcome, engagement_id),
        )
        db.commit()

    def get_engagement(self, engagement_id: int) -> Optional[dict]:
        db = self._get_db()
        row = db.execute("SELECT * FROM engagements WHERE id = ?", (engagement_id,)).fetchone()
        return dict(row) if row else None

    # ── Findings ─────────────────────────────────────────────────────────

    def log_finding(
        self, engagement_id: int, severity: str, category: str, title: str,
        detail: str = "", target_ip: str = "", target_mac: str = "",
    ) -> int:
        db = self._get_db()
        cur = db.execute(
            "INSERT INTO findings (engagement_id, severity, category, title, detail, "
            "target_ip, target_mac, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (engagement_id, severity, category, title, detail, target_ip, target_mac, _now()),
        )
        db.commit()
        return cur.lastrowid

    def query_findings(
        self, engagement_id: int = 0, severity: str = "", category: str = "",
    ) -> list[dict]:
        db = self._get_db()
        clauses, params = [], []
        if engagement_id:
            clauses.append("engagement_id = ?")
            params.append(engagement_id)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if category:
            clauses.append("category = ?")
            params.append(category)
        where = " AND ".join(clauses) if clauses else "1=1"
        rows = db.execute(
            f"SELECT * FROM findings WHERE {where} ORDER BY created_at DESC", params,
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Tool calls ───────────────────────────────────────────────────────

    def log_tool_call(
        self, engagement_id: int = None, tool_name: str = "", action: str = "",
        args_json: str = "{}", result_summary: str = "", success: bool = True,
        blocked: bool = False, block_reason: str = "", duration_ms: int = 0,
        phase: str = "",
    ) -> int:
        db = self._get_db()
        cur = db.execute(
            "INSERT INTO tool_calls (engagement_id, tool_name, action, args_json, "
            "result_summary, success, blocked, block_reason, duration_ms, phase, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (engagement_id, tool_name, action, args_json, result_summary,
             int(success), int(blocked), block_reason, duration_ms, phase, _now()),
        )
        db.commit()
        return cur.lastrowid

    def query_tool_calls(
        self, engagement_id: int = 0, tool_name: str = "", blocked_only: bool = False,
    ) -> list[dict]:
        db = self._get_db()
        clauses, params = [], []
        if engagement_id:
            clauses.append("engagement_id = ?")
            params.append(engagement_id)
        if tool_name:
            clauses.append("tool_name = ?")
            params.append(tool_name)
        if blocked_only:
            clauses.append("blocked = 1")
        where = " AND ".join(clauses) if clauses else "1=1"
        rows = db.execute(
            f"SELECT * FROM tool_calls WHERE {where} ORDER BY created_at DESC", params,
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Phase transitions ────────────────────────────────────────────────

    def log_phase_transition(
        self, engagement_id: int, from_phase: str = "", to_phase: str = "", reason: str = "",
    ) -> int:
        db = self._get_db()
        cur = db.execute(
            "INSERT INTO phase_transitions (engagement_id, from_phase, to_phase, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (engagement_id, from_phase, to_phase, reason, _now()),
        )
        db.commit()
        return cur.lastrowid

    # ── Summary ──────────────────────────────────────────────────────────

    def get_engagement_summary(self, engagement_id: int) -> Optional[dict]:
        eng = self.get_engagement(engagement_id)
        if not eng:
            return None
        db = self._get_db()
        finding_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM findings WHERE engagement_id = ?", (engagement_id,),
        ).fetchone()["cnt"]
        tool_call_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM tool_calls WHERE engagement_id = ?", (engagement_id,),
        ).fetchone()["cnt"]
        blocked_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM tool_calls WHERE engagement_id = ? AND blocked = 1",
            (engagement_id,),
        ).fetchone()["cnt"]
        return {
            **eng,
            "finding_count": finding_count,
            "tool_call_count": tool_call_count,
            "blocked_count": blocked_count,
        }

    def close(self) -> None:
        if self._db:
            self._db.close()
            self._db = None
