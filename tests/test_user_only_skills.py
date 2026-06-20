"""user_only skills (protopen-1hw.8): excluded from auto-retrieval, fetchable by name."""

from __future__ import annotations

import sqlite3

from graph.skills import SkillsIndex
from graph.skills.loader import parse_skill_md, seed_index


def _idx(tmp_path):
    return SkillsIndex(db_path=str(tmp_path / "skills.db"))


def test_user_only_skill_excluded_from_retrieval(tmp_path):
    idx = _idx(tmp_path)
    idx.add_skill("normal_recon", "subnet recon procedure", "do recon", ["dns_enum"])
    idx.add_skill("nuke_target", "destructive teardown procedure", "rm -rf", ["shell"], user_only=True)
    hits = {r.name for r in idx.load_skills("recon procedure destructive teardown", k=10)}
    assert "normal_recon" in hits
    assert "nuke_target" not in hits  # user_only never auto-retrieved


def test_get_skill_returns_user_only_by_name(tmp_path):
    idx = _idx(tmp_path)
    idx.add_skill("nuke_target", "destructive", "the body", ["shell"], user_only=True)
    rec = idx.get_skill("nuke_target")
    assert rec is not None and rec.prompt_template == "the body"
    assert idx.get_skill("missing") is None


def test_all_skills_reports_user_only_flag(tmp_path):
    idx = _idx(tmp_path)
    idx.add_skill("a", "x", "b")
    idx.add_skill("b", "y", "b", user_only=True)
    by_name = {s["name"]: s for s in idx.all_skills()}
    assert by_name["a"]["user_only"] is False
    assert by_name["b"]["user_only"] is True


def test_loader_parses_user_only_frontmatter(tmp_path):
    skill_dir = tmp_path / "nuke"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: nuke\ndescription: destructive teardown\nuser_only: true\n---\nrm the thing\n",
        encoding="utf-8",
    )
    loaded = parse_skill_md(skill_dir / "SKILL.md")
    assert loaded is not None and loaded.user_only is True

    # default is False when the key is absent
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "SKILL.md").write_text("---\nname: plain\ndescription: normal\n---\nbody\n", encoding="utf-8")
    assert parse_skill_md(plain / "SKILL.md").user_only is False


def test_seed_index_threads_user_only(tmp_path):
    (tmp_path / "nuke").mkdir()
    (tmp_path / "nuke" / "SKILL.md").write_text(
        "---\nname: nuke\ndescription: destructive teardown procedure\nuser_only: true\n---\nbody\n",
        encoding="utf-8",
    )
    idx = SkillsIndex(db_path=str(tmp_path / "idx.db"))
    seed_index(idx, [str(tmp_path)])
    assert idx.load_skills("destructive teardown procedure", k=5) == []  # not auto-retrieved
    assert idx.get_skill("nuke") is not None  # but present + fetchable


def test_migration_adds_user_only_column_preserving_rows(tmp_path):
    db = tmp_path / "old.db"
    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE VIRTUAL TABLE skills USING fts5(name, description, prompt_template, tools_used, source UNINDEXED)"
    )
    conn.execute(
        "INSERT INTO skills (name, description, prompt_template, tools_used, source) "
        "VALUES ('old_recon', 'legacy recon', 'body', 'dns_enum', 'emitted')"
    )
    conn.commit()
    conn.close()

    idx = SkillsIndex(db_path=str(db))  # __init__ runs the migration
    cols = [r[1] for r in idx._conn.execute("PRAGMA table_info(skills)").fetchall()]
    assert "user_only" in cols
    # the legacy row survived and is retrievable (defaulted to not-user_only)
    assert idx.get_skill("old_recon") is not None
    assert {r.name for r in idx.load_skills("legacy recon", k=5)} == {"old_recon"}
