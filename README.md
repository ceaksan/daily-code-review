# dnm-audit

Local CLI tool that performs rotating code health audits on your projects using static analysis and dual-LLM review (Claude Code CLI + Gemini CLI).

Not a PR reviewer. Scans your **existing codebase** for accumulated technical debt: duplicated code, architecture violations, complexity, type safety gaps, and resilience issues.

## How It Works

1. **Static scan** (Ruff, radon) pre-filters files and scores complexity
2. **SQLite** tracks file state: hash, complexity, last review lens/date, clean/dirty status
3. **5-lens rotation** reviews code from a different angle each weekday
4. **Dual-LLM** sends selected files to Claude and/or Gemini via their headless CLI modes
5. **Reports** are written as markdown to any directory (Obsidian vault, local folder, etc.)

### Lens Schedule

| Day | Lens | Focus |
|---|---|---|
| Monday | Architecture | Layer violations, pattern compliance, coupling |
| Tuesday | Duplication | Semantic DRY violations, shotgun surgery candidates |
| Wednesday | Complexity | Long functions, deep nesting, SRP violations |
| Thursday | Interfaces | Naming consistency, type safety, API contract drift |
| Friday | Resilience | Error handling, race conditions, N+1 queries, auth gaps |

Files reviewed with one lens are still candidates for other lenses. Clean files (same hash, same lens, zero findings) are skipped. Changed files are always re-reviewed.

## Requirements

- Python 3.12+
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) and/or [Gemini CLI](https://github.com/google-gemini/gemini-cli)
- [Ruff](https://docs.astral.sh/ruff/) (Python linting)
- [radon](https://radon.readthedocs.io/) (cyclomatic complexity)

No pip dependencies. Uses Python stdlib only.

## Setup

```bash
git clone https://github.com/ceaksan/daily-code-review.git
cd daily-code-review

# Create your config
cp lib/config.example.py lib/config.py

# Edit config: set your project paths, LLM CLI paths, output directory
$EDITOR lib/config.py

# Make executable
chmod +x dnm-audit

# Optional: add to PATH
ln -sf $(pwd)/dnm-audit ~/bin/dnm-audit
```

### Config

Edit `lib/config.py` to add your repos:

```python
REPOS = [
    {
        "name": "my-app",
        "path": PROJECTS_DIR / "my-app",
        "architecture": "docs/architecture.md",
        "languages": ["python", "typescript"],
        "source_dirs": ["src/", "apps/"],
        "ignore_dirs": ["node_modules/", "__pycache__/", ".venv/"],
    },
]
```

Each repo needs:
- **name**: identifier used in reports and DB
- **path**: absolute path to repo on disk
- **architecture**: path to architecture doc (relative to repo root)
- **languages**: which static tools to run
- **source_dirs**: directories to scan
- **ignore_dirs**: directories to skip

## Usage

```bash
# Auto: today's lens, all repos
./dnm-audit

# See what would be reviewed without calling LLMs
./dnm-audit --dry-run

# Specific repo
./dnm-audit --repo my-app

# Override lens
./dnm-audit --lens architecture

# Full scan (ignore skip logic, review all files)
./dnm-audit --full

# Use only one LLM
./dnm-audit --llm claude
./dnm-audit --llm gemini

# Run in background
./dnm-audit --quiet &
```

## Output

Reports are written to the configured output directory as markdown:

```
code-reviews/
  2026-03-11/
    my-app.md       # Per-repo findings
    DIGEST.md       # Aggregated summary
```

### Report Format

```markdown
# my-app

- Lens: Architecture
- Date: 2026-03-11 09:30
- Files reviewed: 15 / 120
- Findings: 3

## P0 Critical (1)

### Direct ORM in view
**apps/auth/views.py:42** | architecture

View bypasses service layer, querying DB directly.

**Suggestion**: Move query to AuthService.get_user_by_email()
```

## Architecture

```
dnm-audit              # CLI entry point
lib/
  config.py            # Your paths and repo list (gitignored)
  config.example.py    # Template for config
  db.py                # SQLite state tracking
  scanner.py           # File discovery + static analysis
  reviewer.py          # Claude/Gemini CLI wrapper
  reporter.py          # Markdown report builder
prompts/
  system-base.md       # Base review instructions
  lens-*.md            # 5 lens-specific prompts
tests/                 # 29 tests
```

### State Tracking

SQLite database at `~/.dnm-audit/state.db` tracks:
- File content hashes (detect changes)
- Complexity scores from radon
- Static issue counts from ruff
- Last review lens and date
- Clean/dirty status

Priority queue selects files by `(static_issues * 10 + complexity)` descending, unreviewed files first.

### Customizing Prompts

Edit files in `prompts/` to adjust review criteria. `system-base.md` defines the output JSON format. Each `lens-*.md` defines what to look for in that lens.

## Scheduling

### Option 1: Cron

Best for fully automated daily runs. Works headless, no active session needed.

```bash
# Run every weekday at 09:00
0 9 * * 1-5 /path/to/dnm-audit --quiet >> /tmp/dnm-audit.log 2>&1
```

| Pros | Cons |
|------|------|
| Runs unattended, no open terminal needed | No real-time feedback during review |
| System-level scheduling, survives reboots | Log-only output, need to check reports manually |
| Predictable, fires exactly on schedule | Errors are silent unless you check logs |

### Option 2: Claude Code `/loop`

Best for monitoring candidates during active development sessions. Requires Claude Code CLI.

```bash
# Check candidates every 30 minutes (dry-run, no LLM calls)
/loop 30m ./dnm-audit --dry-run --quiet

# Full review every 2 hours
/loop 2h ./dnm-audit --quiet
```

| Pros | Cons |
|------|------|
| Real-time feedback in your terminal | Only runs while Claude Code session is open |
| Easy to start/stop, no config files | Full review creates nested LLM calls (higher token cost) |
| Good for dry-run monitoring during dev | Not suitable for daily automation |

Both options can be combined: cron for the daily scheduled review, `/loop --dry-run` for candidate awareness during development.

## Local AI Pipeline

Captures every Claude Code edit as structured training data, runs local code reviews with Gemma 4 (via Ollama), and prepares a curated dataset for QLoRA fine-tuning. Goal: reduce cloud API cost by 50-70% while keeping review quality high.

### Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 1. Dataset Collection | Active | PostToolUse hooks capture Edit/Write operations to JSONL |
| 2. Gemma Code Review | Implemented | Gemma 4 reviews via Ollama, critical findings escalate to Opus |
| 3. QLoRA Fine-tuning | Deferred | MLX-Tune on Mac Mini M1 16GB, pending 2,000+ approved examples |

### Dataset

Collected automatically at `~/.claude/datasets/`:

| File | Description |
|------|-------------|
| `opus-interactions.jsonl` | Active dataset (Edit + Write operations with instructions) |
| `opus-interactions-v0.jsonl` | Legacy: 360 records, instruction field empty (pre-fix) |
| `opus-training-approved.jsonl` | Reviewed and approved entries in instruction-tuning format |

### Collection Hooks

| File | Hook | Purpose |
|------|------|---------|
| `~/.claude/hooks/capture-prompt.sh` | UserPromptSubmit | Caches user prompt to /tmp |
| `~/.claude/hooks/training-collector.py` | PostToolUse | Filters and appends Edit/Write to JSONL |
| `~/.claude/hooks/training-review.py` | Standalone CLI | Review, filter, and export collected data |

### Quick Commands

```bash
# Collection statistics
python3 ~/.claude/hooks/training-review.py --stats

# Filter by project or date
python3 ~/.claude/hooks/training-review.py --stats --project daily-code-review
python3 ~/.claude/hooks/training-review.py --stats --since 2026-04-05

# Interactive review (approve/reject pending entries)
python3 ~/.claude/hooks/training-review.py

# Export approved entries for fine-tuning
python3 ~/.claude/hooks/training-review.py --export
```

### References

- [Full spec](docs/superpowers/specs/2026-04-03-local-ai-pipeline-design.md): architecture, data flow, escalation logic, metrics, risk assessment
- [Dataset README](~/.claude/datasets/README.md): JSONL schema, quality filters, collection rate, projections

## Tests

```bash
python -m pytest tests/ -v
```

## License

MIT
