import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from reporter import severity_label, generate_repo_report, generate_digest


def test_severity_label():
    assert severity_label("critical") == "P0"
    assert severity_label("warning") == "P1"
    assert severity_label("info") == "P2"
    assert severity_label("unknown") == "P2"


def test_report_with_findings():
    findings = [
        {
            "title": "Hardcoded secret",
            "severity": "critical",
            "file": "config.py",
            "line": 10,
            "category": "security",
            "detail": "API key exposed in source.",
            "suggestion": "Move to environment variable.",
            "source": "gitleaks",
        },
        {
            "title": "Missing type hint",
            "severity": "info",
            "file": "utils.py",
            "line": 5,
            "category": "typing",
            "detail": "Function lacks return type.",
            "suggestion": "Add -> None.",
        },
    ]
    report = generate_repo_report("my-repo", "security", findings, 8, 12)
    assert "# my-repo" in report
    assert "security" in report
    assert "**Files reviewed**: 8 / 12" in report
    assert "**Findings**: 2" in report
    assert "## P0 Critical (1)" in report
    assert "### Hardcoded secret [gitleaks]" in report
    assert "**config.py:10**" in report
    assert "**Suggestion**: Move to environment variable." in report
    assert "## P2 Info (1)" in report
    assert "### Missing type hint" in report
    # no [source] when source key absent
    assert "### Missing type hint\n" in report


def test_report_clean():
    report = generate_repo_report("clean-repo", "quality", [], 5, 5)
    assert "# clean-repo" in report
    assert "No findings for this lens. Code looks clean." in report
    assert "**Findings**: 0" in report


def test_digest():
    summaries = [
        {
            "repo": "alpha",
            "findings": 3,
            "critical": 1,
            "files_reviewed": 10,
        },
        {
            "repo": "beta",
            "findings": 0,
            "critical": 0,
            "files_reviewed": 5,
        },
    ]
    digest = generate_digest("security", summaries)
    assert "# Code Health Audit" in digest
    assert "security" in digest
    assert "**Repos**: 2" in digest
    assert "**Files**: 15" in digest
    assert "**Findings**: 3" in digest
    assert "**Critical**: 1" in digest
    assert "| alpha | 3 | 1 | 10 |" in digest
    assert "| beta | 0 | 0 | 5 |" in digest
    assert "| Repo | Findings | Critical | Files |" in digest
