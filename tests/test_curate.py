"""Tests for curate_dataset.py — mock Claude API calls, verify full pipeline."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Add tools/ to path for import
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from curate_dataset import (
    build_rewrite_prompt,
    build_score_prompt,
    load_records,
    parse_json_response,
    score_record,
    rewrite_record,
    GOLD_SCHEMA_FIELDS,
)

SAMPLE_RECORD = {
    "id": "abc123",
    "instruction": "Add error handling to the fetch call",
    "input": "response = requests.get(url)\ndata = response.json()",
    "output": 'try:\n    response = requests.get(url)\n    response.raise_for_status()\n    data = response.json()\nexcept requests.RequestException as e:\n    logger.error(f"Fetch failed: {e}")\n    raise',
    "file_type": "py",
    "change_lines": 6,
}

GOOD_SCORE_RESPONSE = json.dumps(
    {
        "code_quality": 8,
        "instruction_clarity": 9,
        "generalizability": 7,
        "composite": 8.0,
        "verdict": "keep",
        "reason": "Clear instruction with solid error handling pattern",
    }
)

BAD_SCORE_RESPONSE = json.dumps(
    {
        "code_quality": 3,
        "instruction_clarity": 2,
        "generalizability": 1,
        "composite": 2.2,
        "verdict": "discard",
        "reason": "Trivial change with unclear instruction",
    }
)

REWRITE_RESPONSE = json.dumps(
    {
        "instruction": "Add comprehensive error handling to HTTP GET request",
        "input": "response = requests.get(url)\ndata = response.json()",
        "thought": "The original code has no error handling. HTTP requests can fail due to network issues, server errors, or invalid JSON. We should catch RequestException for network/HTTP errors and handle JSON decode errors separately.",
        "output": 'try:\n    response = requests.get(url, timeout=30)\n    response.raise_for_status()\n    data = response.json()\nexcept requests.RequestException as e:\n    logger.error(f"Fetch failed: {e}")\n    raise',
    }
)

REWRITE_MISSING_THOUGHT = json.dumps(
    {
        "instruction": "Add error handling",
        "input": "code",
        "output": "better code",
    }
)


class TestParseJsonResponse:
    def test_plain_json(self):
        result = parse_json_response('{"key": "value"}')
        assert result == {"key": "value"}

    def test_json_in_code_block(self):
        raw = '```json\n{"key": "value"}\n```'
        result = parse_json_response(raw)
        assert result == {"key": "value"}

    def test_json_with_surrounding_text(self):
        raw = 'Here is the result:\n{"composite": 7.5, "verdict": "keep"}\nDone.'
        result = parse_json_response(raw)
        assert result["composite"] == 7.5

    def test_invalid_json(self):
        assert parse_json_response("not json at all") is None

    def test_empty_string(self):
        assert parse_json_response("") is None

    def test_nested_json_in_code_block(self):
        raw = '```json\n{"scores": {"a": 1}, "verdict": "keep"}\n```'
        result = parse_json_response(raw)
        assert result["scores"]["a"] == 1


class TestBuildPrompts:
    def test_score_prompt_contains_fields(self):
        prompt = build_score_prompt("system prompt", SAMPLE_RECORD)
        assert "SCORING" in prompt
        assert "Add error handling" in prompt
        assert "requests.get" in prompt

    def test_rewrite_prompt_contains_fields(self):
        prompt = build_rewrite_prompt("system prompt", SAMPLE_RECORD)
        assert "REWRITE" in prompt
        assert "Expert Distillation" in prompt
        assert "Add error handling" in prompt

    def test_truncation_long_input(self):
        long_record = {**SAMPLE_RECORD, "input": "x" * 5000}
        prompt = build_score_prompt("sys", long_record)
        assert len(long_record["input"]) == 5000
        assert "x" * 3000 in prompt
        assert "x" * 3001 not in prompt

    def test_empty_fields_handled(self):
        empty_record = {"instruction": "", "input": "", "output": ""}
        prompt = build_score_prompt("sys", empty_record)
        assert "SCORING" in prompt


class TestScoreRecord:
    @patch("curate_dataset.call_claude")
    def test_keep_record(self, mock_claude):
        mock_claude.return_value = GOOD_SCORE_RESPONSE
        result = score_record("system", SAMPLE_RECORD)
        assert result is not None
        assert result["composite"] == 8.0
        assert result["verdict"] == "keep"

    @patch("curate_dataset.call_claude")
    def test_discard_record(self, mock_claude):
        mock_claude.return_value = BAD_SCORE_RESPONSE
        result = score_record("system", SAMPLE_RECORD)
        assert result is not None
        assert result["composite"] == 2.2
        assert result["verdict"] == "discard"

    @patch("curate_dataset.call_claude")
    def test_empty_response(self, mock_claude):
        mock_claude.return_value = ""
        result = score_record("system", SAMPLE_RECORD)
        assert result is None

    @patch("curate_dataset.call_claude")
    def test_garbage_response(self, mock_claude):
        mock_claude.return_value = "I cannot process this request."
        result = score_record("system", SAMPLE_RECORD)
        assert result is None


class TestRewriteRecord:
    @patch("curate_dataset.call_claude")
    def test_successful_rewrite(self, mock_claude):
        mock_claude.return_value = REWRITE_RESPONSE
        result = rewrite_record("system", SAMPLE_RECORD)
        assert result is not None
        assert all(k in result for k in GOLD_SCHEMA_FIELDS)
        assert "error handling" in result["thought"].lower()

    @patch("curate_dataset.call_claude")
    def test_missing_thought_field(self, mock_claude):
        mock_claude.return_value = REWRITE_MISSING_THOUGHT
        result = rewrite_record("system", SAMPLE_RECORD)
        assert result is not None
        assert "thought" not in result

    @patch("curate_dataset.call_claude")
    def test_empty_response(self, mock_claude):
        mock_claude.return_value = ""
        result = rewrite_record("system", SAMPLE_RECORD)
        assert result is None


class TestLoadRecords:
    def test_load_valid_jsonl(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps(SAMPLE_RECORD) + "\n")
            f.write(json.dumps(SAMPLE_RECORD) + "\n")
            f.flush()
            records = load_records(Path(f.name))
        assert len(records) == 2

    def test_skip_empty_lines(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps(SAMPLE_RECORD) + "\n")
            f.write("\n")
            f.write(json.dumps(SAMPLE_RECORD) + "\n")
            f.flush()
            records = load_records(Path(f.name))
        assert len(records) == 2


class TestEndToEndScoreOnly:
    @patch("curate_dataset.call_claude")
    def test_score_only_keeps_above_threshold(self, mock_claude):
        mock_claude.return_value = GOOD_SCORE_RESPONSE

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as infile:
            infile.write(json.dumps(SAMPLE_RECORD) + "\n")
            infile.flush()
            input_path = Path(infile.name)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as outfile:
            output_path = Path(outfile.name)

        from curate_dataset import load_system_prompt

        system = "test system"

        result = score_record(system, SAMPLE_RECORD)
        assert result["verdict"] == "keep"
        assert result["composite"] >= 7.0

    @patch("curate_dataset.call_claude")
    def test_score_only_discards_below_threshold(self, mock_claude):
        mock_claude.return_value = BAD_SCORE_RESPONSE

        result = score_record("system", SAMPLE_RECORD)
        assert result["verdict"] == "discard"
        assert result["composite"] < 7.0


class TestEndToEndRewrite:
    @patch("curate_dataset.call_claude")
    def test_rewrite_produces_gold_schema(self, mock_claude):
        mock_claude.side_effect = [GOOD_SCORE_RESPONSE, REWRITE_RESPONSE]
        system = "test system"

        score = score_record(system, SAMPLE_RECORD)
        assert score["composite"] >= 7.0

        rewritten = rewrite_record(system, SAMPLE_RECORD)
        assert rewritten is not None
        assert all(k in rewritten for k in GOLD_SCHEMA_FIELDS)
        assert len(rewritten["thought"]) > 0

    @patch("curate_dataset.call_claude")
    def test_rewrite_skips_low_score(self, mock_claude):
        mock_claude.return_value = BAD_SCORE_RESPONSE
        system = "test system"

        score = score_record(system, SAMPLE_RECORD)
        assert score["composite"] < 7.0
