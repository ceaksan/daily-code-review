# daily-code-review

Public repository. Do not commit secrets, API keys, personal paths, or client-specific code.

## Overview

Local CLI tool (dnm-audit) that performs rotating code health audits using static analysis and dual/triple-LLM review. Zero external Python dependencies (stdlib only).

## Stack

- Python 3.12+, stdlib only
- SQLite for state tracking
- Claude CLI + Gemini CLI for LLM reviews
- Ollama for local Gemma inference

## Key Files

- `dnm-audit` - CLI entry point (thin wrapper)
- `dnm_audit/` - Core package (cli, config, scanner, reviewer, reporter, db)
- `prompts/` - System prompts for each LLM and review lens
- `tools/` - Dataset utilities (scrubbing, curation)
- `tests/` - pytest suite
- `docs/adr/` - Architecture Decision Records (gitignored, local only)
- `dnm_audit/config.py` - Repo list and settings (gitignored, local only)

## Conventions

- No external dependencies. Everything is stdlib Python.
- Config is a Python file (config.py), not YAML/JSON. Gitignored because it contains local paths.
- Use config.example.py as template for new setups.
- Tests: `python -m pytest tests/ -v`
- No build step needed.

## Public Repo Rules

- Never hardcode personal paths (/Users/username/...). Use env vars or config.py (gitignored).
- Never commit config.py, architecture.md, or docs/ (all gitignored).
- Never commit .db files (SQLite state).
- Test data in tests/ must use synthetic/fake values only.
- CLAUDE_CMD and similar tool paths must read from environment variables.
