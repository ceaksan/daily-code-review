"""SQLite state tracking for file health."""

import math
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from dnm_audit.config import DAILY_FILE_BUDGET

ISSUE_WEIGHT = 10

PRIORITY_ORDER = f"(static_issues * {ISSUE_WEIGHT} + complexity) DESC"

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS file_health (
    repo TEXT NOT NULL,
    path TEXT NOT NULL,
    content_hash TEXT,
    previous_hash TEXT,
    complexity INTEGER DEFAULT 0,
    static_issues INTEGER DEFAULT 0,
    last_llm_lens TEXT,
    last_llm_date TEXT,
    llm_findings_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'dirty',
    PRIMARY KEY (repo, path)
)
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_repo_status ON file_health (repo, status)",
    "CREATE INDEX IF NOT EXISTS idx_repo_complexity ON file_health (repo, complexity DESC)",
]

CREATE_HISTORY_TABLE = """
CREATE TABLE IF NOT EXISTS review_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    lens TEXT NOT NULL,
    run_date TEXT NOT NULL,
    findings_count INTEGER NOT NULL,
    files_reviewed INTEGER NOT NULL
)
"""

CREATE_HISTORY_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_history_repo_date"
    " ON review_history (repo, run_date DESC)"
)

CREATE_ESCALATIONS_TABLE = """
CREATE TABLE IF NOT EXISTS escalations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    path TEXT NOT NULL,
    lens TEXT NOT NULL,
    run_date TEXT NOT NULL,
    gemma_severity TEXT NOT NULL,
    gemma_confidence REAL,
    gemma_title TEXT NOT NULL,
    gemma_detail TEXT,
    opus_verdict TEXT,
    opus_severity TEXT,
    opus_detail TEXT,
    was_true_positive INTEGER,
    gemma_category TEXT DEFAULT ''
)
"""

CREATE_ESCALATIONS_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_escalations_repo_lens"
    " ON escalations (repo, lens, run_date DESC)"
)

CREATE_ESCALATIONS_CATEGORY_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_escalations_category"
    " ON escalations (gemma_category, run_date DESC)"
)

CREATE_REVIEW_SOURCES_TABLE = """
CREATE TABLE IF NOT EXISTS review_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    path TEXT NOT NULL,
    lens TEXT NOT NULL,
    run_date TEXT NOT NULL,
    llm_source TEXT NOT NULL,
    findings_count INTEGER DEFAULT 0,
    response_time_ms INTEGER
)
"""

CREATE_REVIEW_SOURCES_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_review_sources_repo"
    " ON review_sources (repo, llm_source, run_date DESC)"
)


class HealthDB:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self):
        self._conn.execute(CREATE_TABLE)
        for idx in CREATE_INDEXES:
            self._conn.execute(idx)
        self._conn.execute(CREATE_HISTORY_TABLE)
        self._conn.execute(CREATE_HISTORY_INDEX)
        self._conn.execute(CREATE_ESCALATIONS_TABLE)
        self._conn.execute(CREATE_ESCALATIONS_INDEX)
        # Migration: add gemma_category column to existing escalations tables
        try:
            self._conn.execute(
                "ALTER TABLE escalations ADD COLUMN gemma_category TEXT DEFAULT ''"
            )
        except sqlite3.OperationalError:
            pass  # column already exists
        self._conn.execute(CREATE_ESCALATIONS_CATEGORY_INDEX)
        self._conn.execute(CREATE_REVIEW_SOURCES_TABLE)
        self._conn.execute(CREATE_REVIEW_SOURCES_INDEX)
        self._conn.commit()

    def upsert_file(
        self,
        repo: str,
        path: str,
        content_hash: str,
        complexity: int,
        issues: int,
    ):
        existing = self.get_file(repo, path)
        if existing is None:
            self._conn.execute(
                """INSERT INTO file_health
                   (repo, path, content_hash, complexity, static_issues, status)
                   VALUES (?, ?, ?, ?, ?, 'dirty')""",
                (repo, path, content_hash, complexity, issues),
            )
        else:
            if content_hash != existing["content_hash"]:
                self._conn.execute(
                    """UPDATE file_health
                       SET previous_hash = content_hash,
                           content_hash = ?,
                           complexity = ?,
                           static_issues = ?,
                           status = 'dirty'
                       WHERE repo = ? AND path = ?""",
                    (content_hash, complexity, issues, repo, path),
                )
            else:
                self._conn.execute(
                    """UPDATE file_health
                       SET complexity = ?,
                           static_issues = ?
                       WHERE repo = ? AND path = ?""",
                    (complexity, issues, repo, path),
                )
        self._conn.commit()

    def get_file(self, repo: str, path: str) -> dict | None:
        cur = self._conn.execute(
            "SELECT * FROM file_health WHERE repo = ? AND path = ?",
            (repo, path),
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def mark_reviewed(self, repo: str, path: str, lens: str, findings_count: int):
        status = "clean" if findings_count == 0 else "dirty"
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """UPDATE file_health
               SET last_llm_lens = ?,
                   last_llm_date = ?,
                   llm_findings_count = ?,
                   status = ?
               WHERE repo = ? AND path = ?""",
            (lens, now, findings_count, status, repo, path),
        )
        self._conn.commit()

    def get_candidates(
        self, repo: str, lens: str, limit: int = DAILY_FILE_BUDGET
    ) -> list[dict]:
        cur = self._conn.execute(
            f"""SELECT * FROM file_health
               WHERE repo = ?
                 AND NOT (
                     status = 'clean'
                     AND last_llm_lens = ?
                     AND content_hash = previous_hash
                 )
               ORDER BY
                 {PRIORITY_ORDER},
                 CASE WHEN last_llm_date IS NULL THEN 0 ELSE 1 END,
                 last_llm_date ASC
               LIMIT ?""",
            (repo, lens, limit),
        )
        return [dict(r) for r in cur.fetchall()]

    def get_all_files(self, repo: str) -> list[dict]:
        cur = self._conn.execute(
            f"""SELECT * FROM file_health
               WHERE repo = ?
               ORDER BY {PRIORITY_ORDER}""",
            (repo,),
        )
        return [dict(r) for r in cur.fetchall()]

    def cleanup_removed(self, repo: str, current_files: set):
        cur = self._conn.execute("SELECT path FROM file_health WHERE repo = ?", (repo,))
        db_paths = {row["path"] for row in cur.fetchall()}
        removed = db_paths - current_files
        if removed:
            placeholders = ",".join("?" for _ in removed)
            self._conn.execute(
                f"DELETE FROM file_health WHERE repo = ? AND path IN ({placeholders})",
                [repo, *removed],
            )
            self._conn.commit()

    def insert_history(
        self, repo: str, lens: str, findings_count: int, files_reviewed: int
    ):
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """INSERT INTO review_history
               (repo, lens, run_date, findings_count, files_reviewed)
               VALUES (?, ?, ?, ?, ?)""",
            (repo, lens, now, findings_count, files_reviewed),
        )
        self._conn.commit()

    def get_trends(self, repo: str, limit: int = 14) -> list[dict]:
        cur = self._conn.execute(
            """SELECT repo, lens, run_date, findings_count, files_reviewed
               FROM review_history
               WHERE repo = ?
               ORDER BY id DESC
               LIMIT ?""",
            (repo, limit),
        )
        return [dict(r) for r in cur.fetchall()]

    def get_repo_stats(self, repo: str) -> dict:
        cur = self._conn.execute(
            """SELECT
                 COUNT(*) as total_files,
                 SUM(CASE WHEN status = 'dirty' THEN 1 ELSE 0 END) as dirty_files,
                 SUM(CASE WHEN status = 'clean' THEN 1 ELSE 0 END) as clean_files,
                 AVG(complexity) as avg_complexity
               FROM file_health
               WHERE repo = ?""",
            (repo,),
        )
        row = dict(cur.fetchone())
        return row

    # --- Escalation tracking ---

    def insert_escalation(
        self,
        repo: str,
        path: str,
        lens: str,
        gemma_finding: dict,
        opus_result: dict,
    ):
        now = datetime.now(timezone.utc).isoformat()
        verdict = opus_result.get("opus_verdict", "error")
        was_tp = (
            1 if verdict == "confirmed" else (0 if verdict == "dismissed" else None)
        )
        self._conn.execute(
            """INSERT INTO escalations
               (repo, path, lens, run_date, gemma_severity, gemma_confidence,
                gemma_title, gemma_detail, opus_verdict, opus_severity,
                opus_detail, was_true_positive, gemma_category)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                repo,
                path,
                lens,
                now,
                gemma_finding.get("severity", ""),
                gemma_finding.get("confidence", 0.0),
                gemma_finding.get("title", ""),
                gemma_finding.get("detail", ""),
                verdict,
                opus_result.get("opus_severity", ""),
                opus_result.get("opus_detail", ""),
                was_tp,
                gemma_finding.get("category", ""),
            ),
        )
        self._conn.commit()

    def insert_review_source(
        self,
        repo: str,
        path: str,
        lens: str,
        llm_source: str,
        findings_count: int,
        response_time_ms: int = 0,
    ):
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """INSERT INTO review_sources
               (repo, path, lens, run_date, llm_source, findings_count, response_time_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (repo, path, lens, now, llm_source, findings_count, response_time_ms),
        )
        self._conn.commit()

    def get_escalation_stats(
        self, repo: str | None = None, lens: str | None = None, days: int = 30
    ) -> dict:
        conditions = ["run_date >= date('now', ?  || ' days')"]
        params: list = [f"-{days}"]
        if repo:
            conditions.append("repo = ?")
            params.append(repo)
        if lens:
            conditions.append("lens = ?")
            params.append(lens)
        where = " AND ".join(conditions)
        cur = self._conn.execute(
            f"""SELECT
                 COUNT(*) as total,
                 SUM(CASE WHEN was_true_positive = 1 THEN 1 ELSE 0 END) as confirmed,
                 SUM(CASE WHEN was_true_positive = 0 THEN 1 ELSE 0 END) as dismissed,
                 SUM(CASE WHEN was_true_positive IS NULL THEN 1 ELSE 0 END) as downgraded
               FROM escalations
               WHERE {where}""",
            params,
        )
        row = dict(cur.fetchone())
        total = row["total"] or 0
        row["false_positive_rate"] = (
            round(row["dismissed"] / total, 2) if total > 0 else 0.0
        )
        return row

    def get_false_positive_rate_by_lens(self, days: int = 30) -> dict[str, dict]:
        cur = self._conn.execute(
            """SELECT lens,
                 COUNT(*) as total,
                 SUM(CASE WHEN was_true_positive = 1 THEN 1 ELSE 0 END) as confirmed,
                 SUM(CASE WHEN was_true_positive = 0 THEN 1 ELSE 0 END) as dismissed
               FROM escalations
               WHERE run_date >= date('now', ? || ' days')
               GROUP BY lens""",
            (f"-{days}",),
        )
        result = {}
        for row in cur.fetchall():
            row = dict(row)
            total = row["total"]
            result[row["lens"]] = {
                "total": total,
                "confirmed": row["confirmed"],
                "dismissed": row["dismissed"],
                "false_positive_rate": round(row["dismissed"] / total, 2)
                if total > 0
                else 0.0,
            }
        return result

    # --- Adaptive escalation queries (MBU) ---

    def get_category_accuracy(
        self, category: str, lens: str | None = None, days: int = 60
    ) -> dict:
        """Get true-positive rate for a specific finding category."""
        conditions = [
            "gemma_category = ?",
            "run_date >= date('now', ? || ' days')",
        ]
        params: list = [category, f"-{days}"]
        if lens:
            conditions.append("lens = ?")
            params.append(lens)
        where = " AND ".join(conditions)
        cur = self._conn.execute(
            f"""SELECT
                 COUNT(*) as total,
                 SUM(CASE WHEN was_true_positive = 1 THEN 1 ELSE 0 END) as confirmed,
                 SUM(CASE WHEN was_true_positive = 0 THEN 1 ELSE 0 END) as dismissed
               FROM escalations
               WHERE {where}""",
            params,
        )
        row = dict(cur.fetchone())
        row["total"] = row["total"] or 0
        row["confirmed"] = row["confirmed"] or 0
        row["dismissed"] = row["dismissed"] or 0
        return row

    def get_confidence_stats(self, category: str, days: int = 30) -> dict:
        """Get mean and std of Gemma confidence for a category."""
        cur = self._conn.execute(
            """SELECT
                 COUNT(*) as count,
                 AVG(gemma_confidence) as mean_confidence,
                 AVG(gemma_confidence * gemma_confidence)
                   - AVG(gemma_confidence) * AVG(gemma_confidence) as variance
               FROM escalations
               WHERE gemma_category = ?
                 AND run_date >= date('now', ? || ' days')""",
            (category, f"-{days}"),
        )
        row = dict(cur.fetchone())
        row["count"] = row["count"] or 0
        row["mean_confidence"] = row["mean_confidence"] or 0.0
        row["std_confidence"] = math.sqrt(max(row.get("variance") or 0, 0))
        del row["variance"]
        return row
