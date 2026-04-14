"""Technique library — store and retrieve successful attack techniques."""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DB_PATH = Path(__file__).parent.parent / "data" / "techniques.db"


@dataclass
class Technique:
    """A single attack technique record."""

    id: int = 0
    tool: str = ""
    action: str = ""
    target_type: str = ""  # e.g., "web", "smb", "ssh", "graphql"
    description: str = ""
    payload: str = ""
    waf_bypass: str = ""  # WAF product bypassed, if any
    success: bool = True
    tags: list[str] = field(default_factory=list)
    created_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "action": self.action,
            "target_type": self.target_type,
            "description": self.description,
            "payload": self.payload[:200] if self.payload else "",
            "waf_bypass": self.waf_bypass,
            "success": self.success,
            "tags": self.tags,
        }


class TechniqueLibrary:
    """SQLite-backed library of attack techniques learned from engagements."""

    def __init__(self, db_path: Path | None = None):
        self._db_path = db_path or _DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS techniques (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL DEFAULT '',
                waf_bypass TEXT NOT NULL DEFAULT '',
                success INTEGER NOT NULL DEFAULT 1,
                tags TEXT NOT NULL DEFAULT '[]',
                created_at REAL NOT NULL
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_techniques_tool
            ON techniques(tool, action)
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_techniques_target_type
            ON techniques(target_type)
        """)
        self._conn.commit()

    def add(self, technique: Technique) -> int:
        """Store a technique, return its ID."""
        if not technique.created_at:
            technique.created_at = time.time()
        cur = self._conn.execute(
            """INSERT INTO techniques
               (tool, action, target_type, description, payload,
                waf_bypass, success, tags, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                technique.tool,
                technique.action,
                technique.target_type,
                technique.description,
                technique.payload,
                technique.waf_bypass,
                int(technique.success),
                json.dumps(technique.tags),
                technique.created_at,
            ),
        )
        self._conn.commit()
        technique.id = cur.lastrowid
        return technique.id

    def search(
        self,
        tool: str = "",
        action: str = "",
        target_type: str = "",
        tag: str = "",
        success_only: bool = True,
        limit: int = 20,
    ) -> list[Technique]:
        """Search techniques by tool, action, target type, or tag."""
        conditions = []
        params: list[Any] = []

        if tool:
            conditions.append("tool = ?")
            params.append(tool)
        if action:
            conditions.append("action = ?")
            params.append(action)
        if target_type:
            conditions.append("target_type = ?")
            params.append(target_type)
        if success_only:
            conditions.append("success = 1")
        if tag:
            conditions.append("tags LIKE ?")
            params.append(f"%{tag}%")

        where = " AND ".join(conditions) if conditions else "1=1"
        rows = self._conn.execute(
            f"SELECT * FROM techniques WHERE {where} ORDER BY created_at DESC LIMIT ?",
            params + [limit],
        ).fetchall()

        return [self._row_to_technique(r) for r in rows]

    def get_by_tool(self, tool: str, action: str = "") -> list[Technique]:
        """Get all techniques for a specific tool/action combo."""
        return self.search(tool=tool, action=action, success_only=False)

    def get_waf_bypasses(self, waf_product: str = "") -> list[Technique]:
        """Get WAF bypass techniques."""
        if waf_product:
            rows = self._conn.execute(
                "SELECT * FROM techniques WHERE waf_bypass LIKE ? AND success = 1 ORDER BY created_at DESC",
                (f"%{waf_product}%",),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM techniques WHERE waf_bypass != '' AND success = 1 ORDER BY created_at DESC",
            ).fetchall()
        return [self._row_to_technique(r) for r in rows]

    def stats(self) -> dict[str, Any]:
        """Get library statistics."""
        total = self._conn.execute("SELECT COUNT(*) FROM techniques").fetchone()[0]
        by_tool = self._conn.execute(
            "SELECT tool, COUNT(*) FROM techniques GROUP BY tool ORDER BY COUNT(*) DESC"
        ).fetchall()
        by_type = self._conn.execute(
            "SELECT target_type, COUNT(*) FROM techniques WHERE target_type != '' GROUP BY target_type"
        ).fetchall()
        success_rate = self._conn.execute("SELECT AVG(success) FROM techniques").fetchone()[0]

        return {
            "total": total,
            "by_tool": {r[0]: r[1] for r in by_tool},
            "by_target_type": {r[0]: r[1] for r in by_type},
            "success_rate": round(success_rate or 0, 2),
        }

    def _row_to_technique(self, row: tuple) -> Technique:
        return Technique(
            id=row[0],
            tool=row[1],
            action=row[2],
            target_type=row[3],
            description=row[4],
            payload=row[5],
            waf_bypass=row[6],
            success=bool(row[7]),
            tags=json.loads(row[8]) if row[8] else [],
            created_at=row[9],
        )

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
