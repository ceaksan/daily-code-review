"""Tests for lib/scanner.py"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from scanner import (
    discover_files,
    file_hash,
    parse_radon_output,
    parse_ruff_output,
)


class TestFileHash:
    def test_returns_64_char_hex(self, tmp_path):
        f = tmp_path / "hello.py"
        f.write_text("print('hello')\n")
        h = file_hash(f)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_changes_on_edit(self, tmp_path):
        f = tmp_path / "hello.py"
        f.write_text("v1")
        h1 = file_hash(f)
        f.write_text("v2")
        h2 = file_hash(f)
        assert h1 != h2


class TestDiscoverFiles:
    def test_filters_correctly(self, tmp_path):
        # reviewable
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("")
        (tmp_path / "src" / "index.ts").write_text("")
        # non-reviewable extension
        (tmp_path / "src" / "readme.md").write_text("")
        # ignored dir
        (tmp_path / "src" / "node_modules").mkdir()
        (tmp_path / "src" / "node_modules" / "pkg.js").write_text("")

        result = discover_files(
            repo_path=tmp_path,
            source_dirs=["src/"],
            ignore_dirs=["node_modules/"],
        )
        names = [p.name for p in result]
        assert "app.py" in names
        assert "index.ts" in names
        assert "readme.md" not in names
        assert "pkg.js" not in names
        # sorted
        assert result == sorted(result)


class TestParseRadonOutput:
    def test_parses_complexity(self):
        raw = (
            "src/app.py\n"
            "    F 10:0 foo - A (3)\n"
            "    F 25:0 bar - C (14)\n"
            "src/utils.py\n"
            "    F 1:0 helper - A (1)\n"
        )
        result = parse_radon_output(raw)
        assert result["src/app.py"] == 14
        assert result["src/utils.py"] == 1


class TestParseRuffOutput:
    def test_parses_issue_count(self):
        raw = (
            "src/app.py:10:1: E501 Line too long\n"
            "src/app.py:20:5: F401 Unused import\n"
            "src/utils.py:3:1: E302 Expected 2 blank lines\n"
        )
        result = parse_ruff_output(raw)
        assert result["src/app.py"] == 2
        assert result["src/utils.py"] == 1
