"""Manual --security SAST mode: recon -> detect -> verify over a repo."""

import fnmatch
import hashlib
import logging
import os
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
    ignore_dirs = repo_config.get("ignore_dirs", [])
    ignore_parts = {d.strip("/") for d in ignore_dirs if not d.startswith("*")}
    ignore_globs = [d for d in ignore_dirs if d.startswith("*")]

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
        if any(fnmatch.fnmatch(p.name, g) for g in ignore_globs):
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
            size = p.stat().st_size
        except OSError:
            not_scanned.append({"path": rel, "reason": "unreadable"})
            continue
        inventory.append({"path": rel, "content_hash": content_hash, "size": size})

    inventory.sort(key=lambda e: e["path"])
    not_scanned.sort(key=lambda e: e["path"])
    return inventory, not_scanned


def _prompt_sha(prompt_name: str) -> str:
    p = PROMPTS_SECURITY_DIR / prompt_name
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return "MISSING"


def compute_recon_hash(
    inventory: list[dict], catalog: list[dict], recon_prompt_sha: str
) -> str:
    h = hashlib.sha256()
    for e in sorted(inventory, key=lambda x: x["path"]):
        h.update(f"{e['path']}\x00{e['content_hash']}\x00".encode())
    for c in sorted(catalog, key=lambda x: x["id"]):
        h.update(
            f"{c['id']}\x00{c['title']}\x00{c['prompt']}\x00{c['enabled']}\x00".encode()
        )
        h.update((_prompt_sha(c["prompt"]) + "\x00").encode())
    h.update(recon_prompt_sha.encode())
    return h.hexdigest()


def _is_safe_rel(rel_path: str) -> bool:
    if not rel_path or os.path.isabs(rel_path):
        return False
    norm = os.path.normpath(rel_path)
    return not (norm == ".." or norm.startswith(".." + os.sep))


def guarded_read(repo_root: Path, rel_path: str, inventory_paths: set) -> str | None:
    if not _is_safe_rel(rel_path) or rel_path not in inventory_paths:
        return None
    full = repo_root / rel_path
    try:
        real = full.resolve()
        real.relative_to(repo_root)
    except (ValueError, OSError):
        return None
    try:
        return full.read_text(errors="replace")
    except OSError:
        return None


def chunk_files(
    repo_root: Path, rel_paths: list[str], inventory_paths: set, budget: int
) -> tuple[list[dict], list[dict]]:
    batches: list[dict] = []
    not_scanned: list[dict] = []
    current: dict[str, str] = {}
    current_size = 0

    def flush():
        nonlocal current, current_size
        if current:
            batches.append(current)
            current = {}
            current_size = 0

    for rel in rel_paths:
        text = guarded_read(repo_root, rel, inventory_paths)
        if text is None:
            not_scanned.append({"path": rel, "reason": "unreadable"})
            continue
        if len(text) > budget:
            flush()
            lines = text.splitlines(keepends=True)
            chunk: list[str] = []
            start = 1
            size = 0
            for i, ln in enumerate(lines, start=1):
                chunk.append(ln)
                size += len(ln)
                if size >= budget:
                    batches.append({f"{rel}#L{start}-{i}": "".join(chunk)})
                    chunk = []
                    size = 0
                    start = i + 1
            if chunk:
                batches.append({f"{rel}#L{start}-{len(lines)}": "".join(chunk)})
            continue
        if current_size + len(text) > budget:
            flush()
        current[rel] = text
        current_size += len(text)

    flush()
    return batches, not_scanned
