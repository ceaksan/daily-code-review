"""Dual-LLM reviewer using Claude and Gemini CLI headless modes."""

import json
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


def group_by_directory(files: list[dict], depth: int = 2) -> dict[str, list[dict]]:
    """Group files by parent directory up to given depth."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in files:
        parts = Path(f["path"]).parts
        key = (
            str(Path(*parts[:depth]))
            if len(parts) > depth
            else str(Path(*parts[:-1]))
            if len(parts) > 1
            else str(parts[0])
        )
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

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return result.stdout
    except FileNotFoundError:
        return ""
    except subprocess.TimeoutExpired:
        return ""


def review_batch(
    repo_config: dict,
    candidates: list[dict],
    lens: str,
    llm: LLMChoice,
    quiet: bool = False,
) -> list[dict]:
    """Main entry point: review a batch of files with selected LLMs."""
    # Load prompts
    lens_path = PROMPTS_DIR / f"lens-{lens}.md"
    base_path = PROMPTS_DIR / "system-base.md"

    lens_text = lens_path.read_text() if lens_path.exists() else ""
    base_text = base_path.read_text() if base_path.exists() else ""

    full_lens = f"{base_text}\n\n{lens_text}".strip()

    # Load architecture doc
    arch_doc = ""
    repo_path = Path(repo_config["path"])
    arch_rel = repo_config.get("architecture", "")
    if arch_rel:
        arch_path = repo_path / arch_rel
        if arch_path.exists():
            arch_doc = arch_path.read_text()

    # Group and batch
    groups = group_by_directory(candidates)
    all_findings: list[dict] = []

    # Flatten groups into batches of MAX_FILES_PER_BATCH
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
