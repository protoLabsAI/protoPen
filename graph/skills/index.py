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
    tools_used: tuple[str, ...] = ()


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
            "name, description, prompt_template, tools_used, source UNINDEXED, user_only UNINDEXED)"
        )
        self._migrate_user_only()
        self._conn.commit()

    def _migrate_user_only(self) -> None:
        """Add the user_only column to an older skills.db (FTS5 has no ALTER ADD).

        Preserves rows (emitted skills survive the disk re-seed) by copying them
        into a fresh table with user_only defaulted off. No-op once migrated.
        """
        cols = [r[1] for r in self._conn.execute("PRAGMA table_info(skills)").fetchall()]
        if "user_only" in cols:
            return
        rows = self._conn.execute(
            "SELECT name, description, prompt_template, tools_used, source FROM skills"
        ).fetchall()
        self._conn.executescript(
            "DROP TABLE skills;"
            "CREATE VIRTUAL TABLE skills USING fts5("
            "name, description, prompt_template, tools_used, source UNINDEXED, user_only UNINDEXED);"
        )
        self._conn.executemany(
            "INSERT INTO skills (name, description, prompt_template, tools_used, source, user_only) "
            "VALUES (?, ?, ?, ?, ?, '0')",
            rows,
        )

    def add_skill(
        self,
        name: str,
        description: str,
        prompt_template: str,
        tools_used: list[str] | None = None,
        *,
        source: str = "disk",
        user_only: bool = False,
    ) -> None:
        self._conn.execute(
            "INSERT INTO skills (name, description, prompt_template, tools_used, source, user_only) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (name, description, prompt_template, " ".join(tools_used or []), source, "1" if user_only else "0"),
        )
        self._conn.commit()

    def clear_source(self, source: str = "disk") -> None:
        """Drop all skills from a source — used to re-seed disk skills each boot."""
        self._conn.execute("DELETE FROM skills WHERE source = ?", (source,))
        self._conn.commit()

    def add_emitted_skill(
        self, name: str, description: str, prompt_template: str, tools_used: list[str] | None = None
    ) -> None:
        """Persist an agent-authored skill (source='emitted'). Overwrites any
        existing skill of the same name (so re-saving refines rather than
        duplicates), and survives the per-boot disk re-seed."""
        self._conn.execute("DELETE FROM skills WHERE name = ?", (name,))
        self.add_skill(name, description, prompt_template, tools_used, source="emitted")

    def load_skills(self, query: str, k: int = 5) -> list[SkillRecord]:
        match = _build_match_query(query)
        if not match:
            return []
        try:
            # user_only skills are never auto-retrieved into context — they're
            # deliberate, run-on-demand procedures (protopen-1hw.8).
            rows = self._conn.execute(
                "SELECT name, description, prompt_template, tools_used, bm25(skills) AS score "
                "FROM skills WHERE skills MATCH ? AND user_only = '0' ORDER BY score LIMIT ?",
                (match, max(1, int(k))),
            ).fetchall()
        except sqlite3.OperationalError as exc:  # malformed MATCH — never raise into the turn
            log.debug("[skills] match query failed: %s", exc)
            return []
        return [
            SkillRecord(
                name=r[0],
                description=r[1],
                prompt_template=r[2],
                score=r[4],
                tools_used=tuple((r[3] or "").split()),
            )
            for r in rows
        ]

    def get_skill(self, name: str) -> SkillRecord | None:
        """Fetch a skill by exact name — including user_only ones (for explicit,
        on-demand invocation that bypasses auto-retrieval)."""
        row = self._conn.execute(
            "SELECT name, description, prompt_template, tools_used FROM skills WHERE name = ? LIMIT 1",
            (name,),
        ).fetchone()
        if row is None:
            return None
        return SkillRecord(
            name=row[0],
            description=row[1],
            prompt_template=row[2],
            score=0.0,
            tools_used=tuple((row[3] or "").split()),
        )

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM skills").fetchone()[0]

    def all_skills(self, query: str = "", limit: int = 200) -> list[dict]:
        """List skills for the operator console — name, description, declared
        tools, and source (disk vs emitted). Newest-ish first, or relevance-ranked
        when a query is given. Never raises into the caller."""
        q = (query or "").strip()
        try:
            if q:
                match = _build_match_query(q)
                if not match:
                    return []
                rows = self._conn.execute(
                    "SELECT name, description, tools_used, source, user_only FROM skills "
                    "WHERE skills MATCH ? ORDER BY bm25(skills) LIMIT ?",
                    (match, max(1, int(limit))),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT name, description, tools_used, source, user_only FROM skills LIMIT ?",
                    (max(1, int(limit)),),
                ).fetchall()
        except sqlite3.OperationalError as exc:
            log.debug("[skills] all_skills failed: %s", exc)
            return []
        return [
            {
                "name": r[0],
                "description": r[1],
                "tools": (r[2] or "").split(),
                "source": r[3] or "disk",
                "user_only": str(r[4] or "0") == "1",
            }
            for r in rows
        ]
