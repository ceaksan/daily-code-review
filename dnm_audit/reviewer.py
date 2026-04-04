"""Triple-LLM reviewer using Claude, Gemini CLI headless modes and Gemma via Ollama."""

import json
import logging
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

from dnm_audit.config import (
    CLAUDE_CMD,
    DEFAULT_CATEGORY_ADJUSTMENTS,
    ESCALATION_CATEGORIES,
    ESCALATION_CONFIDENCE_THRESHOLD,
    ESCALATION_THRESHOLD_CEILING,
    ESCALATION_THRESHOLD_FLOOR,
    GEMINI_CMD,
    GEMMA_MAX_CHARS_PER_BATCH,
    MAX_CHARS_PER_BATCH,
    MAX_FILES_PER_BATCH,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT_CONNECT,
    OLLAMA_TIMEOUT_READ,
    PROMPTS_DIR,
)

logger = logging.getLogger(__name__)

LLM_TIMEOUT = 300
DEFAULT_GROUP_DEPTH = 2


class LLMChoice:
    """Wraps the user's LLM selection."""

    def __init__(self, choice: str):
        choice = choice.lower().strip()
        self.use_claude = choice in ("claude", "both", "all")
        self.use_gemini = choice in ("gemini", "both", "all")
        self.use_gemma = choice in ("gemma", "gemma+opus", "all")
        self.escalate_to_opus = choice in ("gemma+opus", "all")


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


def read_file_contents(
    repo_path: Path, file_paths: list[str], budget: int = MAX_CHARS_PER_BATCH
) -> dict[str, str]:
    """Read files respecting a character budget."""
    contents: dict[str, str] = {}

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


# --- Ollama / Gemma ---


def check_ollama_health() -> bool:
    """Quick check if Ollama is reachable. Returns True/False."""
    try:
        req = urllib.request.Request(f"{OLLAMA_BASE_URL}/api/tags")
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT_CONNECT) as resp:
            return resp.status == 200
    except Exception:
        return False


def call_ollama(prompt: str, quiet: bool = False) -> tuple[str, int]:
    """Call Gemma via Ollama HTTP API.

    Returns (response_text, response_time_ms). Returns ('', 0) on failure.
    """
    url = f"{OLLAMA_BASE_URL}/api/generate"
    payload = json.dumps(
        {
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 4096},
        }
    ).encode()

    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    start = time.monotonic()
    try:
        timeout = OLLAMA_TIMEOUT_CONNECT + OLLAMA_TIMEOUT_READ
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode())
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return body.get("response", ""), elapsed_ms
    except urllib.error.URLError as e:
        if not quiet:
            logger.warning("Ollama unreachable: %s", e)
        return "", 0
    except Exception as e:
        if not quiet:
            logger.warning("Ollama call failed: %s", e)
        return "", 0


def build_gemma_prompt(
    lens_text: str,
    architecture: str,
    file_contents: dict[str, str],
    static_summary: str,
) -> str:
    """Build Gemma-specific review prompt with confidence/escalation fields."""
    gemma_system_path = PROMPTS_DIR / "system-gemma.md"
    gemma_base = gemma_system_path.read_text() if gemma_system_path.exists() else ""

    parts = [
        gemma_base,
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


def build_escalation_prompt(finding: dict, file_content: str) -> str:
    """Construct the Opus verification prompt for an escalated finding."""
    escalation_path = PROMPTS_DIR / "system-escalation.md"
    system_text = escalation_path.read_text() if escalation_path.exists() else ""

    return f"""{system_text}

## Finding from Local LLM (Gemma)
{json.dumps(finding, indent=2)}

## Source Code
```
{file_content}
```

Analyze whether this finding is valid. Return a single JSON object:
{{"verdict": "confirmed|downgraded|dismissed", "severity": "critical|warning|info", "detail": "Your analysis", "suggestion": "Updated suggestion if any"}}
"""


def get_adaptive_threshold(category: str, lens: str | None = None, db=None) -> float:
    """Compute effective escalation threshold using historical accuracy.

    When enough historical data exists (>=5 samples), adjusts the base
    threshold based on true-positive rate for this category. Otherwise
    falls back to static defaults from config.
    """
    base = ESCALATION_CONFIDENCE_THRESHOLD

    if db is not None:
        stats = db.get_category_accuracy(category, lens)
        if stats["total"] >= 5:
            tp_rate = stats["confirmed"] / stats["total"]
            # Range: [-0.15, +0.15]. High tp_rate = lower threshold.
            adjustment = (tp_rate - 0.5) * 0.3
            return max(
                ESCALATION_THRESHOLD_FLOOR,
                min(ESCALATION_THRESHOLD_CEILING, base - adjustment),
            )

    # Not enough history: use static defaults
    adjustment = DEFAULT_CATEGORY_ADJUSTMENTS.get(category, 0.0)
    return max(
        ESCALATION_THRESHOLD_FLOOR,
        min(ESCALATION_THRESHOLD_CEILING, base - adjustment),
    )


def is_confidence_anomaly(
    category: str,
    confidence: float,
    db=None,
    days: int = 30,
    _stats_cache: dict[str, dict] | None = None,
) -> bool:
    """Flag if confidence is unusually high/low for this category."""
    if _stats_cache is not None and category in _stats_cache:
        stats = _stats_cache[category]
    elif db is not None:
        stats = db.get_confidence_stats(category, days)
    else:
        return False
    if stats["count"] < 10:
        return False
    std = stats["std_confidence"]
    if std < 0.05:
        return abs(confidence - stats["mean_confidence"]) > 0.2
    z = (confidence - stats["mean_confidence"]) / std
    return abs(z) > 2.0


def should_escalate(
    finding: dict,
    db=None,
    lens: str | None = None,
    _threshold_cache: dict[str, float] | None = None,
) -> bool:
    """Determine if a Gemma finding should be escalated to Opus.

    Uses per-category significance weights and adaptive thresholds
    based on historical Opus verdict accuracy. Backwards compatible:
    db=None falls back to static defaults.
    """
    severity = finding.get("severity", "").lower()
    if severity == "critical":
        return True
    if finding.get("needs_escalation", False):
        return True
    if severity == "warning":
        confidence = finding.get("confidence", 0.0)
        category = finding.get("category", "").lower()
        weight = ESCALATION_CATEGORIES.get(category, 0.0)
        if weight == 0.0:
            return False
        weighted_confidence = confidence * weight
        if _threshold_cache is not None and category in _threshold_cache:
            threshold = _threshold_cache[category]
        else:
            threshold = get_adaptive_threshold(category, lens, db)
        return weighted_confidence >= threshold
    return False


def parse_opus_verdict(raw: str) -> dict:
    """Parse Opus escalation response into a verdict dict."""
    # Try ```json block
    m = re.search(r"```(?:json)?\s*\n(\{[\s\S]*?\})\s*\n```", raw)
    if m:
        try:
            return json.loads(m.group(1))
        except (json.JSONDecodeError, ValueError):
            pass
    # Try plain JSON object
    m = re.search(r"\{[\s\S]*\}", raw)
    if m:
        try:
            return json.loads(m.group(0))
        except (json.JSONDecodeError, ValueError):
            pass
    return {"verdict": "error", "detail": "Failed to parse Opus response"}


def escalate_findings(
    findings: list[dict],
    repo_path: Path,
    file_contents: dict[str, str],
    quiet: bool = False,
) -> list[dict]:
    """Send escalation-worthy findings to Opus for verification."""
    results = []
    for finding in findings:
        file_path = finding.get("file", "")
        content = file_contents.get(file_path, "")
        prompt = build_escalation_prompt(finding, content)
        raw = call_llm(CLAUDE_CMD, prompt, quiet=quiet)
        verdict = parse_opus_verdict(raw)
        results.append(
            {
                "gemma_finding": finding,
                "opus_verdict": verdict.get("verdict", "error"),
                "opus_severity": verdict.get("severity", finding.get("severity")),
                "opus_detail": verdict.get("detail", ""),
                "opus_suggestion": verdict.get("suggestion", ""),
            }
        )
    return results


# --- Prompt loading ---


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


# --- Main entry point ---


def review_batch(
    repo_config: dict,
    candidates: list[dict],
    lens: str,
    llm: LLMChoice,
    quiet: bool = False,
    db=None,
) -> list[dict]:
    """Main entry point: review a batch of files with selected LLMs."""
    full_lens = _load_prompts(lens)
    arch_doc = _load_architecture(repo_config)
    repo_path = Path(repo_config["path"])
    batched = _build_batches(candidates)

    all_findings: list[dict] = []
    escalation_results: list[dict] = []

    for batch in batched:
        file_paths = [f["path"] for f in batch]

        static_summary = "\n".join(
            f.get("static_summary", "") for f in batch if f.get("static_summary")
        )

        # Claude review
        if llm.use_claude:
            contents = read_file_contents(repo_path, file_paths)
            if contents:
                prompt = build_prompt(full_lens, arch_doc, contents, static_summary)
                raw = call_llm(CLAUDE_CMD, prompt, quiet=quiet)
                all_findings.extend(parse_findings(raw))

        # Gemini review
        if llm.use_gemini:
            contents = read_file_contents(repo_path, file_paths)
            if contents:
                prompt = build_prompt(full_lens, arch_doc, contents, static_summary)
                raw = call_llm(GEMINI_CMD, prompt, quiet=quiet)
                findings = parse_findings(raw)
                for f in findings:
                    f["source"] = "gemini"
                all_findings.extend(findings)

        # Gemma review (via Ollama)
        if llm.use_gemma and repo_config.get("gemma_enabled", False):
            contents = read_file_contents(
                repo_path, file_paths, budget=GEMMA_MAX_CHARS_PER_BATCH
            )
            if contents:
                prompt = build_gemma_prompt(
                    full_lens, arch_doc, contents, static_summary
                )
                raw, response_ms = call_ollama(prompt, quiet=quiet)
                if raw:
                    findings = parse_findings(raw)
                    for f in findings:
                        f["source"] = "gemma"
                        f.setdefault("confidence", 0.5)
                        f.setdefault("needs_escalation", False)
                    all_findings.extend(findings)

                    # Escalation to Opus
                    if llm.escalate_to_opus:
                        # Pre-fetch per-category stats to avoid N+1 queries
                        _threshold_cache: dict[str, float] = {}
                        _conf_stats_cache: dict[str, dict] = {}
                        if db is not None:
                            cats = {
                                f.get("category", "").lower()
                                for f in findings
                                if f.get("category")
                            }
                            for cat in cats:
                                _threshold_cache[cat] = get_adaptive_threshold(
                                    cat, lens, db
                                )
                                _conf_stats_cache[cat] = db.get_confidence_stats(cat)

                        to_escalate = [
                            f
                            for f in findings
                            if should_escalate(
                                f,
                                db=None,
                                lens=lens,
                                _threshold_cache=_threshold_cache,
                            )
                        ]
                        if to_escalate:
                            # Tag anomalous confidence for Opus prompt
                            for ef in to_escalate:
                                cat = ef.get("category", "").lower()
                                conf = ef.get("confidence", 0.0)
                                if is_confidence_anomaly(
                                    cat,
                                    conf,
                                    db=None,
                                    _stats_cache=_conf_stats_cache,
                                ):
                                    ef["confidence_anomaly"] = True
                            results = escalate_findings(
                                to_escalate, repo_path, contents, quiet=quiet
                            )
                            escalation_results.extend(results)

                            # Enrich findings with Opus verdicts
                            for esc in results:
                                gemma_f = esc["gemma_finding"]
                                gemma_f["opus_verdict"] = esc["opus_verdict"]
                                gemma_f["opus_severity"] = esc["opus_severity"]
                                gemma_f["opus_detail"] = esc["opus_detail"]

    # Attach escalation results to the return for db.py to process
    if escalation_results:
        for f in all_findings:
            if f.get("source") == "gemma" and "opus_verdict" in f:
                f["_escalation"] = True

    return all_findings
