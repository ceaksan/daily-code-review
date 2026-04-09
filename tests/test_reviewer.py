"""Tests for lib/reviewer.py"""

import json
from pathlib import Path

from dnm_audit.reviewer import (
    LLMChoice,
    build_prompt,
    group_by_directory,
    parse_findings,
    parse_opus_verdict,
    should_escalate,
)


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


class TestLLMChoice:
    def test_both(self):
        c = LLMChoice("both")
        assert c.use_claude
        assert c.use_gemini
        assert not c.use_gemma
        assert not c.escalate_to_opus

    def test_gemma_opus(self):
        c = LLMChoice("gemma+opus")
        assert not c.use_claude
        assert not c.use_gemini
        assert c.use_gemma
        assert c.escalate_to_opus

    def test_all(self):
        c = LLMChoice("all")
        assert c.use_claude
        assert c.use_gemini
        assert c.use_gemma
        assert c.escalate_to_opus

    def test_gemma_only(self):
        c = LLMChoice("gemma")
        assert not c.use_claude
        assert not c.use_gemini
        assert c.use_gemma
        assert not c.escalate_to_opus


class TestShouldEscalate:
    def test_critical_always_escalates(self):
        f = {"severity": "critical", "confidence": 0.3, "category": "complexity"}
        assert should_escalate(f)

    def test_needs_escalation_flag(self):
        f = {"severity": "warning", "confidence": 0.5, "needs_escalation": True}
        assert should_escalate(f)

    def test_warning_high_confidence_security(self):
        f = {"severity": "warning", "confidence": 0.9, "category": "security"}
        assert should_escalate(f)

    def test_warning_low_confidence_no_escalate(self):
        f = {"severity": "warning", "confidence": 0.3, "category": "security"}
        assert not should_escalate(f)

    def test_warning_high_confidence_non_security(self):
        f = {"severity": "warning", "confidence": 0.9, "category": "complexity"}
        assert not should_escalate(f)

    def test_info_never_escalates(self):
        f = {"severity": "info", "confidence": 1.0, "category": "security"}
        assert not should_escalate(f)


class TestShadowMode:
    def test_shadow_mode_escalates_all(self, tmp_path):
        from unittest.mock import patch

        from dnm_audit.reviewer import review_batch, LLMChoice

        repo_path = tmp_path / "repo"
        repo_path.mkdir()
        (repo_path / "src").mkdir()
        (repo_path / "src" / "app.py").write_text("print('hello')")

        repo_config = {
            "name": "test-repo",
            "path": repo_path,
            "architecture": "",
            "languages": ["python"],
            "source_dirs": ["src/"],
            "ignore_dirs": [],
            "gemma_enabled": True,
        }

        candidates = [{"path": "src/app.py", "complexity": 5, "static_issues": 0}]
        llm = LLMChoice("gemma+opus")

        low_finding = {
            "file": "src/app.py",
            "severity": "info",
            "confidence": 0.2,
            "category": "duplication",
            "title": "Minor dup",
            "detail": "Not important",
            "needs_escalation": False,
        }
        gemma_response = json.dumps([low_finding])
        opus_response = '{"verdict": "dismissed", "severity": "info", "detail": "Not real", "suggestion": ""}'

        with (
            patch("dnm_audit.reviewer.SHADOW_MODE", True),
            patch("dnm_audit.reviewer.call_ollama", return_value=(gemma_response, 100)),
            patch("dnm_audit.reviewer.call_llm", return_value=opus_response),
        ):
            findings = review_batch(
                repo_config=repo_config,
                candidates=candidates,
                lens="duplication",
                llm=llm,
                quiet=True,
            )

        escalated = [f for f in findings if f.get("_escalation")]
        assert len(escalated) == 1
        assert escalated[0]["_shadow_decision"] is False
        assert escalated[0]["opus_verdict"] == "dismissed"


class TestParseOpusVerdict:
    def test_json_block(self):
        raw = '```json\n{"verdict": "confirmed", "severity": "critical", "detail": "Valid", "suggestion": "Fix it"}\n```'
        v = parse_opus_verdict(raw)
        assert v["verdict"] == "confirmed"

    def test_plain_json(self):
        raw = '{"verdict": "dismissed", "detail": "False positive"}'
        v = parse_opus_verdict(raw)
        assert v["verdict"] == "dismissed"

    def test_invalid_returns_error(self):
        raw = "This is not JSON"
        v = parse_opus_verdict(raw)
        assert v["verdict"] == "error"
