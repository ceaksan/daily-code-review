"""Tests for lib/scanner.py"""

import json
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
    def test_ruff_select_flag_in_command(self, monkeypatch, tmp_path):
        """Verify run_tool receives --select flag when RUFF_SELECT is set."""
        import scanner

        calls = []

        def fake_run_tool(cmd, cwd):
            calls.append(cmd)
            return ""

        monkeypatch.setattr(scanner, "run_tool", fake_run_tool)
        monkeypatch.setattr(scanner, "RUFF_SELECT", "E,F,I,UP,B,SIM")

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x = 1\n")

        scanner.scan_repo(
            {
                "path": str(tmp_path),
                "source_dirs": ["src/"],
                "ignore_dirs": [],
                "languages": ["python"],
            }
        )
        ruff_calls = [c for c in calls if "ruff" in c[0]]
        assert any("--select" in c for c in ruff_calls)

    def test_parses_issue_count(self):
        raw = (
            "src/app.py:10:1: E501 Line too long\n"
            "src/app.py:20:5: F401 Unused import\n"
            "src/utils.py:3:1: E302 Expected 2 blank lines\n"
        )
        result = parse_ruff_output(raw)
        assert result["src/app.py"] == 2
        assert result["src/utils.py"] == 1


class TestParseEslintOutput:
    def test_parses_json_output(self):
        from scanner import parse_eslint_output

        raw = json.dumps(
            [
                {"filePath": "src/app.ts", "errorCount": 2, "warningCount": 3},
                {"filePath": "src/utils.ts", "errorCount": 0, "warningCount": 1},
            ]
        )
        result = parse_eslint_output(raw)
        assert result["src/app.ts"] == 5
        assert result["src/utils.ts"] == 1

    def test_empty_json_array(self):
        from scanner import parse_eslint_output

        result = parse_eslint_output("[]")
        assert result == {}

    def test_invalid_json(self):
        from scanner import parse_eslint_output

        result = parse_eslint_output("not json")
        assert result == {}
