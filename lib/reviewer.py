"""Dual-LLM reviewer using Claude and Gemini CLI headless modes."""

import json
import logging
import os
import re
import subprocess
from collections import defaultdict
from pathlib import Path

from config import (
    CLAUDE_CMD,
    GEMINI_CMD,
    MAX_CHARS_PER_BATCH,
    MAX_FILES_PER_BATCH,
    PROMPTS_DIR,
)

logger = logging.getLogger(__name__)

LLM_TIMEOUT = 300
DEFAULT_GROUP_DEPTH = 2


class LLMChoice:
    """Wraps the user's LLM selection."""

    def __init__(self, choice: str):
        choice = choice.lower().strip()
        self.use_claude = choice in ("claude", "both")
        self.use_gemini = choice in ("gemini", "both")


def parse_findings(raw: str) -> list[dict]:
    """Extract JSON array from LLM output.

    Handles ```json blocks, plain JSON, and surrounding text.
    Returns [] on parse failure.
    """
    # Try ```json code block first
    m = re.search(r"```(?:json)?\s*\n(\[[\s\S]*?\])\s*\n```", raw)
    if m:
        try:
            return json.loads(m.group(1))
        except (json.JSONDecodeError, ValueError):
            pass

    # Try finding a JSON array directly
    m = re.search(r"\[[\s\S]*\]", raw)
    if m:
        try:
            return json.loads(m.group(0))
        except (json.JSONDecodeError, ValueError):
            pass

    return []


def group_by_directory(
    files: list[dict], depth: int = DEFAULT_GROUP_DEPTH
) -> dict[str, list[dict]]:
    """Group files by parent directory up to given depth."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in files:
        parts = Path(f["path"]).parts
        if len(parts) > depth:
            key = str(Path(*parts[:depth]))
        elif len(parts) > 1:
            key = str(Path(*parts[:-1]))
        else:
            key = str(parts[0])
        groups[key].append(f)
    return dict(groups)


def build_prompt(
    lens_text: str,
    architecture: str,
    file_contents: dict[str, str],
    static_summary: str,
) -> str:
    """Build the full review prompt."""
    parts = [
        lens_text,
        f"## Architecture\n\n{architecture}",
        f"## Static Analysis\n\n{static_summary}",
        "## Source Code\n",
    ]
    for filepath, content in file_contents.items():
        ext = Path(filepath).suffix.lstrip(".")
        parts.append(f"### {filepath}\n```{ext}\n{content}\n```")

    parts.append(
        "Review these files through the lens above. Return findings as a JSON array."
    )
    return "\n\n".join(parts)


def read_file_contents(repo_path: Path, file_paths: list[str]) -> dict[str, str]:
    """Read files respecting MAX_CHARS_PER_BATCH budget."""
    contents: dict[str, str] = {}
    budget = MAX_CHARS_PER_BATCH

    for fp in file_paths:
        full = repo_path / fp
        if not full.is_file():
            continue
        try:
            text = full.read_text(errors="replace")
        except OSError:
            continue
        if len(text) > budget:
            break
        contents[fp] = text
        budget -= len(text)

    return contents


def call_llm(cmd: str, prompt: str, quiet: bool = False) -> str:
    """Call LLM CLI in headless mode. Returns stdout or '' on failure."""
    args = [cmd, "-p", prompt]
    if cmd == CLAUDE_CMD:
        args.extend(["--output-format", "text"])

    env = os.environ.copy()
    env.pop("CLAUDECODE", None)

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=LLM_TIMEOUT,
            env=env,
        )
        return result.stdout
    except FileNotFoundError:
        logger.warning("LLM CLI not found: %s", cmd)
        return ""
    except subprocess.TimeoutExpired:
        logger.warning("LLM timed out after %ds: %s", LLM_TIMEOUT, cmd)
        return ""


def _load_prompts(lens: str) -> str:
    """Load and combine base + lens-specific prompts."""
    lens_path = PROMPTS_DIR / f"lens-{lens}.md"
    base_path = PROMPTS_DIR / "system-base.md"
    lens_text = lens_path.read_text() if lens_path.exists() else ""
    base_text = base_path.read_text() if base_path.exists() else ""
    return f"{base_text}\n\n{lens_text}".strip()


def _load_architecture(repo_config: dict) -> str:
    """Load repo's architecture doc if available."""
    repo_path = Path(repo_config["path"])
    arch_rel = repo_config.get("architecture", "")
    if arch_rel:
        arch_path = repo_path / arch_rel
        if arch_path.exists():
            return arch_path.read_text()
    return ""


def _build_batches(candidates: list[dict]) -> list[list[dict]]:
    """Group candidates by directory and split into batches."""
    groups = group_by_directory(candidates)
    batched: list[list[dict]] = []
    current_batch: list[dict] = []
    for group_files in groups.values():
        for f in group_files:
            current_batch.append(f)
            if len(current_batch) >= MAX_FILES_PER_BATCH:
                batched.append(current_batch)
                current_batch = []
    if current_batch:
        batched.append(current_batch)
    return batched


def review_batch(
    repo_config: dict,
    candidates: list[dict],
    lens: str,
    llm: LLMChoice,
    quiet: bool = False,
) -> list[dict]:
    """Main entry point: review a batch of files with selected LLMs."""
    full_lens = _load_prompts(lens)
    arch_doc = _load_architecture(repo_config)
    repo_path = Path(repo_config["path"])
    batched = _build_batches(candidates)

    all_findings: list[dict] = []
    for batch in batched:
        file_paths = [f["path"] for f in batch]
        contents = read_file_contents(repo_path, file_paths)
        if not contents:
            continue

        static_summary = "\n".join(
            f.get("static_summary", "") for f in batch if f.get("static_summary")
        )
        prompt = build_prompt(full_lens, arch_doc, contents, static_summary)

        if llm.use_claude:
            raw = call_llm(CLAUDE_CMD, prompt, quiet=quiet)
            all_findings.extend(parse_findings(raw))

        if llm.use_gemini:
            raw = call_llm(GEMINI_CMD, prompt, quiet=quiet)
            findings = parse_findings(raw)
            for f in findings:
                f["source"] = "gemini"
            all_findings.extend(findings)

    return all_findings
