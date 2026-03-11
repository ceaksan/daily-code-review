"""Tests for HealthDB SQLite state tracking."""

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from db import HealthDB


def _make_db(tmp_path):
    return HealthDB(tmp_path / "test.db")


def test_init_creates_table(tmp_path):
    db = _make_db(tmp_path)
    import sqlite3

    conn = sqlite3.connect(tmp_path / "test.db")
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='file_health'"
    )
    assert cur.fetchone() is not None
    conn.close()


def test_upsert_new_file(tmp_path):
    db = _make_db(tmp_path)
    db.upsert_file("repo1", "src/app.py", "abc123", 5, 2)
    row = db.get_file("repo1", "src/app.py")
    assert row is not None
    assert row["content_hash"] == "abc123"
    assert row["complexity"] == 5
    assert row["static_issues"] == 2
    assert row["status"] == "dirty"
    assert row["previous_hash"] is None


def test_upsert_tracks_previous_hash(tmp_path):
    db = _make_db(tmp_path)
    db.upsert_file("repo1", "src/app.py", "hash1", 5, 2)
    db.upsert_file("repo1", "src/app.py", "hash2", 6, 3)
    row = db.get_file("repo1", "src/app.py")
    assert row["content_hash"] == "hash2"
    assert row["previous_hash"] == "hash1"
    assert row["status"] == "dirty"


def test_unchanged_hash_keeps_clean(tmp_path):
    db = _make_db(tmp_path)
    db.upsert_file("repo1", "src/app.py", "hash1", 5, 2)
    db.mark_reviewed("repo1", "src/app.py", "complexity", 0)
    row = db.get_file("repo1", "src/app.py")
    assert row["status"] == "clean"

    db.upsert_file("repo1", "src/app.py", "hash1", 5, 2)
    row = db.get_file("repo1", "src/app.py")
    assert row["status"] == "clean"


def test_changed_hash_marks_dirty(tmp_path):
    db = _make_db(tmp_path)
    db.upsert_file("repo1", "src/app.py", "hash1", 5, 2)
    db.mark_reviewed("repo1", "src/app.py", "complexity", 0)
    assert db.get_file("repo1", "src/app.py")["status"] == "clean"

    db.upsert_file("repo1", "src/app.py", "hash2", 5, 2)
    assert db.get_file("repo1", "src/app.py")["status"] == "dirty"


def test_mark_reviewed_clean(tmp_path):
    db = _make_db(tmp_path)
    db.upsert_file("repo1", "src/app.py", "hash1", 5, 2)
    db.mark_reviewed("repo1", "src/app.py", "architecture", 0)
    row = db.get_file("repo1", "src/app.py")
    assert row["status"] == "clean"
    assert row["last_llm_lens"] == "architecture"
    assert row["last_llm_date"] is not None
    assert row["llm_findings_count"] == 0


def test_mark_reviewed_dirty_with_findings(tmp_path):
    db = _make_db(tmp_path)
    db.upsert_file("repo1", "src/app.py", "hash1", 5, 2)
    db.mark_reviewed("repo1", "src/app.py", "complexity", 3)
    row = db.get_file("repo1", "src/app.py")
    assert row["status"] == "dirty"
    assert row["llm_findings_count"] == 3


def test_candidates_prioritize_hot_files(tmp_path):
    db = _make_db(tmp_path)
    db.upsert_file("repo1", "low.py", "h1", 1, 0)
    db.upsert_file("repo1", "high.py", "h2", 10, 5)
    db.upsert_file("repo1", "mid.py", "h3", 5, 2)

    candidates = db.get_candidates("repo1", "complexity")
    paths = [c["path"] for c in candidates]
    assert paths[0] == "high.py"
    assert paths[-1] == "low.py"


def test_candidates_skip_same_lens_clean(tmp_path):
    db = _make_db(tmp_path)
    db.upsert_file("repo1", "src/app.py", "hash1", 5, 2)
    db.mark_reviewed("repo1", "src/app.py", "complexity", 0)

    candidates = db.get_candidates("repo1", "complexity")
    paths = [c["path"] for c in candidates]
    assert "src/app.py" not in paths


def test_candidates_include_different_lens(tmp_path):
    db = _make_db(tmp_path)
    db.upsert_file("repo1", "src/app.py", "hash1", 5, 2)
    db.mark_reviewed("repo1", "src/app.py", "complexity", 0)

    candidates = db.get_candidates("repo1", "architecture")
    paths = [c["path"] for c in candidates]
    assert "src/app.py" in paths


def test_get_all_files(tmp_path):
    db = _make_db(tmp_path)
    db.upsert_file("repo1", "a.py", "h1", 1, 0)
    db.upsert_file("repo1", "b.py", "h2", 10, 5)

    files = db.get_all_files("repo1")
    assert len(files) == 2
    assert files[0]["path"] == "b.py"


def test_cleanup_removed(tmp_path):
    db = _make_db(tmp_path)
    db.upsert_file("repo1", "keep.py", "h1", 1, 0)
    db.upsert_file("repo1", "remove.py", "h2", 1, 0)

    db.cleanup_removed("repo1", {"keep.py"})
    assert db.get_file("repo1", "keep.py") is not None
    assert db.get_file("repo1", "remove.py") is None


def test_repo_stats(tmp_path):
    db = _make_db(tmp_path)
    db.upsert_file("repo1", "a.py", "h1", 4, 0)
    db.upsert_file("repo1", "b.py", "h2", 8, 2)
    db.mark_reviewed("repo1", "a.py", "complexity", 0)

    stats = db.get_repo_stats("repo1")
    assert stats["total_files"] == 2
    assert stats["clean_files"] == 1
    assert stats["dirty_files"] == 1
    assert stats["avg_complexity"] == 6.0
