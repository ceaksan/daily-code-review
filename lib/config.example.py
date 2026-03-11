"""Configuration for dnm-audit. Copy this to config.py and edit."""

from pathlib import Path

# Base paths
PROJECTS_DIR = Path.home() / "projects"
VAULT_DIR = Path.home() / "vault" / "code-reviews"  # Obsidian vault or any markdown dir
DB_PATH = Path.home() / ".dnm-audit" / "state.db"
PROMPTS_DIR = Path(__file__).parent.parent / "prompts"

# LLM CLI commands (use `which claude` / `which gemini` to find paths)
CLAUDE_CMD = "claude"
GEMINI_CMD = "gemini"

# Static tools
RUFF_CMD = "ruff"
RADON_CMD = "radon"

# Review settings
DAILY_FILE_BUDGET = 15
MAX_FILES_PER_BATCH = 5
MAX_CHARS_PER_BATCH = 200_000  # ~50K tokens

# Lens schedule (weekday index -> lens name)
LENS_SCHEDULE = {
    0: "architecture",  # Monday
    1: "duplication",  # Tuesday
    2: "complexity",  # Wednesday
    3: "interfaces",  # Thursday
    4: "resilience",  # Friday
}

# Repos to audit — add your own
REPOS = [
    {
        "name": "my-app",
        "path": PROJECTS_DIR / "my-app",
        "architecture": "docs/architecture.md",
        "languages": ["python", "typescript"],
        "source_dirs": ["src/", "apps/"],
        "ignore_dirs": [
            "node_modules/",
            ".next/",
            "migrations/",
            "__pycache__/",
            ".venv/",
        ],
    },
]

# File extensions to review
REVIEWABLE_EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".jsx"}
