"""SQLite FTS5 skill index for protoPen.

Stores skills (name + description + instruction body) in a full-text search
index so the agent can retrieve relevant skills at inference time. Human-authored
``SKILL.md`` files are re-seeded from disk on each boot (source='disk').

Focused for slice 1 — discovery + retrieval. No schema migration / curator /
agent-emitted persistence (those are later slices in protoAgent's roadmap).
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
from typing import NamedTuple

log = logging.getLogger(__name__)


def _build_match_query(query: str) -> str:
    """Free text → a safe FTS5 prefix-OR MATCH expression.

    A bare FTS5 query is an implicit AND, so one non-matching word zeroes the
    result. We OR each token as a prefix (``term*``) — matches morphological
    variants, ranks by BM25. Tokenizing to ``\\w+`` strips FTS5 syntax chars, so
    arbitrary user text can't raise a query error.
    """
    terms = re.findall(r"\w+", query.lower())
    return " OR ".join(f"{t}*" for t in terms)


class SkillRecord(NamedTuple):
    """A single result from FTS5 skill retrieval (score = BM25, lower is better)."""

    name: str
    description: str
    prompt_template: str
    score: float


class SkillsIndex:
    """SQLite FTS5-backed skill index. ``add_skill`` then ``load_skills(query, k)``."""

    def __init__(self, db_path: str = "/sandbox/skills.db") -> None:
        self._db_path = db_path
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS skills USING fts5("
            "name, description, prompt_template, tools_used, source UNINDEXED)"
        )
        self._conn.commit()

    def add_skill(
        self,
        name: str,
        description: str,
        prompt_template: str,
        tools_used: list[str] | None = None,
        *,
        source: str = "disk",
    ) -> None:
        self._conn.execute(
            "INSERT INTO skills (name, description, prompt_template, tools_used, source) VALUES (?, ?, ?, ?, ?)",
            (name, description, prompt_template, " ".join(tools_used or []), source),
        )
        self._conn.commit()

    def clear_source(self, source: str = "disk") -> None:
        """Drop all skills from a source — used to re-seed disk skills each boot."""
        self._conn.execute("DELETE FROM skills WHERE source = ?", (source,))
        self._conn.commit()

    def load_skills(self, query: str, k: int = 5) -> list[SkillRecord]:
        match = _build_match_query(query)
        if not match:
            return []
        try:
            rows = self._conn.execute(
                "SELECT name, description, prompt_template, bm25(skills) AS score "
                "FROM skills WHERE skills MATCH ? ORDER BY score LIMIT ?",
                (match, max(1, int(k))),
            ).fetchall()
        except sqlite3.OperationalError as exc:  # malformed MATCH — never raise into the turn
            log.debug("[skills] match query failed: %s", exc)
            return []
        return [SkillRecord(name=r[0], description=r[1], prompt_template=r[2], score=r[3]) for r in rows]

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM skills").fetchone()[0]
