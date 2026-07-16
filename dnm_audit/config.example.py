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
ESLINT_CMD = "eslint"

# Ruff rule selection (comma-separated rule codes)
# E=pycodestyle, F=pyflakes, I=isort, UP=pyupgrade, B=flake8-bugbear, SIM=flake8-simplify
RUFF_SELECT = "E,F,I,UP,B,SIM"

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
            "venv/",
        ],
    },
]

# File extensions to review
REVIEWABLE_EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".jsx"}

# --- Security mode (--security) ---
# All optional; security.py falls back to built-in defaults via getattr.
SECURITY_EXTENSIONS = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".yml",
    ".yaml",
    ".json",
    ".tf",
    ".sh",
    ".conf",
    ".ini",
    ".toml",
    ".env",
}
SECURITY_FILE_PATTERNS = [
    "Dockerfile*",
    ".env*",
    "*.tfvars",
    "docker-compose*.yml",
    "*.yml",
]
SECURITY_SOURCE_DIRS = None  # None = reuse each repo's source_dirs
SECURITY_MAX_FINDINGS_PER_CLASS = 30
SECURITY_MAX_FINDINGS_TOTAL = 120
SECURITY_MIN_VERIFY_PER_CLASS = 3
# SECURITY_CATALOG defaults to the built-in 13-class list; override to add/remove classes.
