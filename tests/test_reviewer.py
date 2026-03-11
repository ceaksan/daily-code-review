"""Tests for lib/reviewer.py"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from reviewer import build_prompt, group_by_directory, parse_findings


class TestParseFindings:
    def test_json_code_block(self):
        raw = '```json\n[{"file": "a.py", "severity": "high"}]\n```'
        result = parse_findings(raw)
        assert len(result) == 1
        assert result[0]["file"] == "a.py"

    def test_plain_json(self):
        raw = '[{"file": "b.py", "severity": "low"}]'
        result = parse_findings(raw)
        assert len(result) == 1
        assert result[0]["file"] == "b.py"

    def test_empty_array(self):
        raw = "[]"
        result = parse_findings(raw)
        assert result == []

    def test_invalid_returns_empty(self):
        raw = "This is not JSON at all."
        result = parse_findings(raw)
        assert result == []

    def test_surrounding_text(self):
        raw = (
            "Here are my findings:\n"
            '```json\n[{"file": "c.py", "issue": "bad"}]\n```\n'
            "Hope this helps!"
        )
        result = parse_findings(raw)
        assert len(result) == 1
        assert result[0]["file"] == "c.py"


class TestBuildPrompt:
    def test_contains_all_parts(self):
        prompt = build_prompt(
            lens_text="Check for complexity.",
            architecture="Monolith with modules.",
            file_contents={"src/app.py": "print('hello')"},
            static_summary="ruff: 2 issues",
        )
        assert "Check for complexity." in prompt
        assert "## Architecture" in prompt
        assert "Monolith with modules." in prompt
        assert "## Static Analysis" in prompt
        assert "ruff: 2 issues" in prompt
        assert "## Source Code" in prompt
        assert "### src/app.py" in prompt
        assert "print('hello')" in prompt
        assert "Return findings as a JSON array" in prompt


class TestGroupByDirectory:
    def test_groups_correctly(self):
        files = [
            {"path": "src/api/routes.py"},
            {"path": "src/api/models.py"},
            {"path": "src/utils/helpers.py"},
            {"path": "lib/core.py"},
        ]
        groups = group_by_directory(files, depth=2)
        assert "src/api" in groups
        assert len(groups["src/api"]) == 2
        assert "src/utils" in groups
        assert len(groups["src/utils"]) == 1
        assert "lib" in groups or "lib/core.py" in str(groups)
