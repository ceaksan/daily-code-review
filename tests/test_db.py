"""Tests for HealthDB SQLite state tracking."""

import sqlite3
from datetime import datetime
from pathlib import Path

from dnm_audit.db import HealthDB


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


def test_insert_history(tmp_path):
    db = _make_db(tmp_path)
    db.insert_history("repo1", "complexity", 5, 15)
    db.insert_history("repo1", "architecture", 3, 12)

    rows = db.get_trends("repo1")
    assert len(rows) == 2
    lenses = {r["lens"] for r in rows}
    assert "complexity" in lenses
    assert "architecture" in lenses


def test_get_trends_limit(tmp_path):
    db = _make_db(tmp_path)
    for i in range(20):
        db.insert_history("repo1", "complexity", i, 10)

    rows = db.get_trends("repo1", limit=7)
    assert len(rows) == 7


# --- Escalation tracking tests ---


def test_escalations_table_created(tmp_path):
    db = _make_db(tmp_path)
    conn = sqlite3.connect(tmp_path / "test.db")
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='escalations'"
    )
    assert cur.fetchone() is not None
    conn.close()


def test_review_sources_table_created(tmp_path):
    db = _make_db(tmp_path)
    conn = sqlite3.connect(tmp_path / "test.db")
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='review_sources'"
    )
    assert cur.fetchone() is not None
    conn.close()


def test_insert_escalation(tmp_path):
    db = _make_db(tmp_path)
    gemma_finding = {
        "severity": "critical",
        "confidence": 0.9,
        "title": "SQL injection risk",
        "detail": "User input not sanitized",
    }
    opus_result = {
        "opus_verdict": "confirmed",
        "opus_severity": "critical",
        "opus_detail": "Valid finding, user input goes directly to query",
    }
    db.insert_escalation("repo1", "src/db.py", "resilience", gemma_finding, opus_result)

    stats = db.get_escalation_stats(repo="repo1")
    assert stats["total"] == 1
    assert stats["confirmed"] == 1
    assert stats["dismissed"] == 0


def test_insert_escalation_dismissed(tmp_path):
    db = _make_db(tmp_path)
    gemma_finding = {
        "severity": "critical",
        "confidence": 0.6,
        "title": "False alarm",
        "detail": "Looks wrong",
    }
    opus_result = {
        "opus_verdict": "dismissed",
        "opus_severity": "info",
        "opus_detail": "Not an issue",
    }
    db.insert_escalation(
        "repo1", "src/safe.py", "resilience", gemma_finding, opus_result
    )

    stats = db.get_escalation_stats(repo="repo1")
    assert stats["total"] == 1
    assert stats["dismissed"] == 1
    assert stats["false_positive_rate"] == 1.0


def test_insert_review_source(tmp_path):
    db = _make_db(tmp_path)
    db.insert_review_source("repo1", "src/app.py", "complexity", "gemma", 3, 5000)
    db.insert_review_source("repo1", "src/app.py", "complexity", "claude", 2, 0)

    # Just verify no errors; these are write-only for now
    stats = db.get_escalation_stats(repo="repo1")
    assert stats["total"] == 0  # no escalations, just sources


def test_false_positive_rate_by_lens(tmp_path):
    db = _make_db(tmp_path)
    # 2 confirmed, 1 dismissed in complexity
    for title in ("Bug 1", "Bug 2"):
        db.insert_escalation(
            "repo1",
            "f.py",
            "complexity",
            {"severity": "critical", "confidence": 0.9, "title": title, "detail": ""},
            {
                "opus_verdict": "confirmed",
                "opus_severity": "critical",
                "opus_detail": "",
            },
        )
    db.insert_escalation(
        "repo1",
        "g.py",
        "complexity",
        {"severity": "critical", "confidence": 0.5, "title": "FP", "detail": ""},
        {"opus_verdict": "dismissed", "opus_severity": "info", "opus_detail": ""},
    )

    rates = db.get_false_positive_rate_by_lens()
    assert "complexity" in rates
    assert rates["complexity"]["total"] == 3
    assert rates["complexity"]["confirmed"] == 2
    assert rates["complexity"]["dismissed"] == 1
    assert rates["complexity"]["false_positive_rate"] == round(1 / 3, 2)


def test_escalation_stats_empty(tmp_path):
    db = _make_db(tmp_path)
    stats = db.get_escalation_stats()
    assert stats["total"] == 0
    assert stats["false_positive_rate"] == 0.0
