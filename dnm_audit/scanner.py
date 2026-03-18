"""File discovery and static analysis."""

import fnmatch
import hashlib
import json
import logging
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from dnm_audit.config import ESLINT_CMD, REVIEWABLE_EXTENSIONS, RUFF_SELECT

logger = logging.getLogger(__name__)

TOOL_TIMEOUT = 120


def file_hash(path: Path) -> str:
    """SHA-256 hash of file contents."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def discover_files(
    repo_path: Path,
    source_dirs: list[str],
    ignore_dirs: list[str],
) -> list[Path]:
    """Find all reviewable files in source_dirs, excluding ignore_dirs. Sorted."""
    repo_path = Path(repo_path)
    ignore_parts = {d.strip("/") for d in ignore_dirs if not d.startswith("*")}
    ignore_globs = [d for d in ignore_dirs if d.startswith("*")]
    found: list[Path] = []

    for sd in source_dirs:
        base = repo_path / sd
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix not in REVIEWABLE_EXTENSIONS:
                continue
            if any(part in ignore_parts for part in p.relative_to(repo_path).parts):
                continue
            if any(fnmatch.fnmatch(p.name, g) for g in ignore_globs):
                continue
            found.append(p)

    return sorted(found)


def parse_radon_output(raw: str) -> dict[str, int]:
    """Parse radon cc output, return {filepath: max_complexity}."""
    result: dict[str, int] = {}
    current_file = None
    complexity_re = re.compile(r"\((\d+)\)\s*$")

    for line in raw.splitlines():
        if not line:
            continue
        if not line[0].isspace():
            current_file = line.strip()
            if current_file not in result:
                result[current_file] = 0
        elif current_file is not None:
            m = complexity_re.search(line)
            if m:
                val = int(m.group(1))
                if val > result[current_file]:
                    result[current_file] = val

    return result


def parse_ruff_output(raw: str) -> dict[str, int]:
    """Parse ruff output, return {filepath: issue_count}."""
    result: dict[str, int] = {}
    for line in raw.splitlines():
        if not line.strip():
            continue
        # format: filepath:line:col: CODE message
        parts = line.split(":", 3)
        if len(parts) >= 4:
            fp = parts[0]
            result[fp] = result.get(fp, 0) + 1
    return result


def parse_eslint_output(raw: str) -> dict[str, int]:
    """Parse eslint --format json output, return {filepath: error+warning count}."""
    try:
        entries = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {}
    result: dict[str, int] = {}
    for entry in entries:
        fp = entry.get("filePath", "")
        count = entry.get("errorCount", 0) + entry.get("warningCount", 0)
        if fp and count > 0:
            result[fp] = count
    return result


def run_tool(cmd: list[str], cwd: Path) -> str:
    """Run subprocess, return stdout+stderr. Logs warnings on failure."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
        )
        return proc.stdout + proc.stderr
    except FileNotFoundError:
        logger.warning("Tool not found: %s", cmd[0])
        return ""
    except subprocess.TimeoutExpired:
        logger.warning("Tool timed out after %ds: %s", TOOL_TIMEOUT, cmd[0])
        return ""


def scan_repo(repo_config: dict) -> list[dict]:
    """Discover files, run radon+ruff for python repos, return file info dicts."""
    repo_path = Path(repo_config["path"])
    source_dirs = repo_config.get("source_dirs", [])
    ignore_dirs = repo_config.get("ignore_dirs", [])
    languages = repo_config.get("languages", [])

    files = discover_files(repo_path, source_dirs, ignore_dirs)

    complexity_map: dict[str, int] = {}
    issues_map: dict[str, int] = {}

    if "python" in languages:
        py_files = [str(f.relative_to(repo_path)) for f in files if f.suffix == ".py"]
        if py_files:
            ruff_cmd = [
                "ruff",
                "check",
                "--output-format",
                "concise",
                "--select",
                RUFF_SELECT,
            ]
            with ThreadPoolExecutor(max_workers=2) as pool:
                radon_future = pool.submit(
                    run_tool, ["radon", "cc", "-s"] + py_files, repo_path
                )
                ruff_future = pool.submit(run_tool, ruff_cmd + py_files, repo_path)
                complexity_map = parse_radon_output(radon_future.result())
                issues_map = parse_ruff_output(ruff_future.result())

    if any(lang in languages for lang in ("typescript", "javascript")):
        ts_exts = {".ts", ".tsx", ".js", ".jsx"}
        ts_files = [str(f.relative_to(repo_path)) for f in files if f.suffix in ts_exts]
        if ts_files:
            eslint_raw = run_tool(
                [ESLINT_CMD, "--format", "json"] + ts_files,
                cwd=repo_path,
            )
            eslint_map = parse_eslint_output(eslint_raw)
            for fp, count in eslint_map.items():
                try:
                    rel = str(Path(fp).relative_to(repo_path))
                except ValueError:
                    rel = fp
                issues_map[rel] = issues_map.get(rel, 0) + count

    results: list[dict] = []
    for f in files:
        rel = str(f.relative_to(repo_path))
        results.append(
            {
                "path": rel,
                "hash": file_hash(f),
                "complexity": complexity_map.get(rel, 0),
                "issues": issues_map.get(rel, 0),
            }
        )

    return results
