"""Manual --security SAST mode: recon -> detect -> verify over a repo."""

import fnmatch
import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

PROMPTS_SECURITY_DIR = Path(__file__).parent.parent / "prompts" / "security"

_DEFAULT_CATALOG = [
    {"id": "sqli", "title": "SQL Injection", "prompt": "sec-sqli.md", "enabled": True},
    {
        "id": "xss",
        "title": "Cross-Site Scripting",
        "prompt": "sec-xss.md",
        "enabled": True,
    },
    {
        "id": "rce",
        "title": "Remote Code Execution",
        "prompt": "sec-rce.md",
        "enabled": True,
    },
    {
        "id": "ssrf",
        "title": "Server-Side Request Forgery",
        "prompt": "sec-ssrf.md",
        "enabled": True,
    },
    {
        "id": "jwt",
        "title": "JWT / Session Flaws",
        "prompt": "sec-jwt.md",
        "enabled": True,
    },
    {
        "id": "path-traversal",
        "title": "Path Traversal",
        "prompt": "sec-path-traversal.md",
        "enabled": True,
    },
    {
        "id": "access-control",
        "title": "Broken Access Control (IDOR)",
        "prompt": "sec-access-control.md",
        "enabled": True,
    },
    {
        "id": "ssti",
        "title": "Server-Side Template Injection",
        "prompt": "sec-ssti.md",
        "enabled": True,
    },
    {
        "id": "deserialization",
        "title": "Insecure Deserialization",
        "prompt": "sec-deserialization.md",
        "enabled": True,
    },
    {
        "id": "xxe",
        "title": "XML External Entity",
        "prompt": "sec-xxe.md",
        "enabled": True,
    },
    {
        "id": "open-redirect",
        "title": "Open Redirect",
        "prompt": "sec-open-redirect.md",
        "enabled": True,
    },
    {
        "id": "secrets",
        "title": "Hardcoded Secrets",
        "prompt": "sec-secrets.md",
        "enabled": True,
    },
    {
        "id": "business-logic",
        "title": "Business Logic Flaws",
        "prompt": "sec-business-logic.md",
        "enabled": True,
    },
]

SECURITY_DEFAULTS = {
    "SECURITY_EXTENSIONS": {
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
    },
    "SECURITY_FILE_PATTERNS": [
        "Dockerfile*",
        ".env*",
        "*.tfvars",
        "docker-compose*.yml",
        "*.yml",
    ],
    "SECURITY_SOURCE_DIRS": None,  # None => use repo_config["source_dirs"]
    "SECURITY_CATALOG": _DEFAULT_CATALOG,
    "SECURITY_MAX_FINDINGS_PER_CLASS": 30,
    "SECURITY_MAX_FINDINGS_TOTAL": 120,
    "SECURITY_MIN_VERIFY_PER_CLASS": 3,
}

_REQUIRED_CATALOG_FIELDS = ("id", "title", "prompt", "enabled")


def get_setting(config, name: str):
    return getattr(config, name, SECURITY_DEFAULTS[name])


def _validate_prompt_name(prompt: str) -> None:
    if (
        not prompt
        or "/" in prompt
        or "\\" in prompt
        or ".." in prompt
        or Path(prompt).is_absolute()
    ):
        raise ValueError(f"invalid prompt filename: {prompt!r}")


def load_catalog(config) -> list[dict]:
    catalog = get_setting(config, "SECURITY_CATALOG")
    seen: set[str] = set()
    enabled: list[dict] = []
    for entry in catalog:
        for field in _REQUIRED_CATALOG_FIELDS:
            if field not in entry:
                raise ValueError(f"catalog entry missing field {field!r}: {entry!r}")
        cid = entry["id"]
        if cid in seen:
            raise ValueError(f"duplicate catalog id: {cid!r}")
        seen.add(cid)
        _validate_prompt_name(entry["prompt"])
        if entry["enabled"]:
            enabled.append(entry)
    return enabled


def matches_security_file(name: str, extensions: set, patterns: list) -> bool:
    if Path(name).suffix in extensions:
        return True
    return any(fnmatch.fnmatch(name, pat) for pat in patterns)


def _iter_candidate_files(repo_root: Path, walk_dirs: list[str]):
    """Yield files under walk_dirs plus repo-root top-level files."""
    seen: set[Path] = set()
    for sd in walk_dirs:
        base = repo_root / sd
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if p not in seen:
                seen.add(p)
                yield p
    for p in repo_root.iterdir():  # top-level files only
        if p.is_file() and p not in seen:
            seen.add(p)
            yield p


def build_inventory(repo_config: dict, config) -> tuple[list[dict], list[dict]]:
    repo_root = Path(repo_config["path"]).resolve()
    extensions = get_setting(config, "SECURITY_EXTENSIONS")
    patterns = get_setting(config, "SECURITY_FILE_PATTERNS")
    override = get_setting(config, "SECURITY_SOURCE_DIRS")
    source_dirs = (
        override if override is not None else repo_config.get("source_dirs", [])
    )
    walk_dirs = list(source_dirs) + [".github"]
    ignore_parts = {
        d.strip("/")
        for d in repo_config.get("ignore_dirs", [])
        if not d.startswith("*")
    }

    inventory: list[dict] = []
    not_scanned: list[dict] = []

    for p in _iter_candidate_files(repo_root, walk_dirs):
        try:
            if not p.is_file():
                continue
        except OSError:
            continue
        if not matches_security_file(p.name, extensions, patterns):
            continue
        try:
            rel_for_ignore = p.relative_to(repo_root)
        except ValueError:
            rel = None
        else:
            rel = str(rel_for_ignore)
        if rel is None:
            continue
        if any(part in ignore_parts for part in rel_for_ignore.parts):
            continue
        # symlink containment
        try:
            real = p.resolve()
            real.relative_to(repo_root)
        except (ValueError, OSError):
            not_scanned.append({"path": rel, "reason": "symlink-escape"})
            continue
        try:
            content_hash = hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            not_scanned.append({"path": rel, "reason": "unreadable"})
            continue
        inventory.append(
            {"path": rel, "content_hash": content_hash, "size": p.stat().st_size}
        )

    inventory.sort(key=lambda e: e["path"])
    not_scanned.sort(key=lambda e: e["path"])
    return inventory, not_scanned
