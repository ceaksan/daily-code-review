"""SQLite state tracking for file health."""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from config import DAILY_FILE_BUDGET

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
            """SELECT * FROM file_health
               WHERE repo = ?
                 AND NOT (
                     status = 'clean'
                     AND last_llm_lens = ?
                     AND content_hash = previous_hash
                 )
               ORDER BY
                 (static_issues * 10 + complexity) DESC,
                 CASE WHEN last_llm_date IS NULL THEN 0 ELSE 1 END,
                 last_llm_date ASC
               LIMIT ?""",
            (repo, lens, limit),
        )
        return [dict(r) for r in cur.fetchall()]

    def get_all_files(self, repo: str) -> list[dict]:
        cur = self._conn.execute(
            """SELECT * FROM file_health
               WHERE repo = ?
               ORDER BY (static_issues * 10 + complexity) DESC""",
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
