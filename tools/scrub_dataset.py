#!/usr/bin/env python3
"""Strip secrets, credentials, and PII from training JSONL files.

Standalone CLI, zero external dependencies (stdlib only, Python 3.12+).
Reads JSONL from stdin or --input, writes cleaned JSONL to stdout or --output.
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # AWS Access Keys
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    # AWS Secret Keys (40 chars after known prefixes)
    (
        "aws_secret_key",
        re.compile(
            r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey)"
            r"""[\s]*[=:]\s*["']?([A-Za-z0-9/+=]{40})"""
        ),
    ),
    # JWT tokens (must come before generic Bearer to get specific match)
    (
        "jwt_token",
        re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ),
    # Bearer / OAuth tokens
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}")),
    # Shopify tokens
    ("shopify_token", re.compile(r"shp(?:at|ss)_[a-fA-F0-9]{20,}")),
    # Database URLs
    (
        "database_url",
        re.compile(r"(?:postgresql|mysql|mongodb|redis)://[^\s\"']+"),
    ),
    # SSH private keys
    ("ssh_private_key", re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----")),
    # .env-style secrets (KEY=value patterns)
    (
        "env_secret",
        re.compile(
            r"(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIALS|AUTH)[_A-Z]*"
            r"""\s*[=:]\s*["']?([^\s"'\[\]]{8,})"""
        ),
    ),
    # Generic API keys (api_key=..., apikey=..., api-key: ...)
    (
        "api_key",
        re.compile(
            r"""(?:api[_-]?key|apikey)\s*[=:]\s*["']?([A-Za-z0-9_\-]{16,})""",
            re.IGNORECASE,
        ),
    ),
    # Internal domains
    (
        "internal_domain",
        re.compile(r"(?:dnomia\.app|ceaksan\.com|dnomia\.com|leetty\.com)"),
    ),
    # Email addresses
    (
        "email",
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    ),
    # Private IP addresses
    (
        "private_ip",
        re.compile(r"(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
    ),
    # Generic JSON secret values ("secret_key": "value", "password": "value")
    (
        "json_secret",
        re.compile(
            r"""["'](?:secret[_-]?key|password|passwd|private[_-]?key|"""
            r"""access[_-]?token|refresh[_-]?token|client[_-]?secret|"""
            r"""auth[_-]?token|encryption[_-]?key)["']\s*:\s*["']([^"']{8,})["']""",
            re.IGNORECASE,
        ),
    ),
]

# Fields that contain code/prompts and need scrubbing
SCRUB_FIELDS = {"input", "output", "instruction"}

# Fields that should never be scrubbed
PASSTHROUGH_FIELDS = {
    "id",
    "ts",
    "session_id",
    "project",
    "tool_name",
    "file_type",
    "status",
    "change_lines",
    "truncated",
}

# Home directory prefix to strip from file_path
_HOME_RE = re.compile(r"/Users/[^/]+/")


# ---------------------------------------------------------------------------
# Core scrubbing logic
# ---------------------------------------------------------------------------


def scrub_text(text: str, counts: Counter[str]) -> str:
    """Apply all regex patterns to a string, replacing matches with redaction tags."""
    if not text:
        return text

    for label, pattern in PATTERNS:
        tag = f"[REDACTED:{label}]"

        if label in ("aws_secret_key", "env_secret", "api_key", "json_secret"):
            # These patterns capture the secret in group(1); replace only the group
            def _make_replacer(lbl: str, tg: str) -> callable:
                def _replacer(m: re.Match) -> str:
                    counts[lbl] += 1
                    full = m.group(0)
                    secret = m.group(1)
                    return full.replace(secret, tg)

                return _replacer

            text, n = pattern.subn(_make_replacer(label, tag), text)
        else:
            new_text = pattern.sub(tag, text)
            n = (
                (len(text) - len(new_text) + len(tag)) // max(1, len(tag))
                if new_text != text
                else 0
            )
            # More reliable count: just count substitutions
            n = len(pattern.findall(text))
            if n > 0:
                counts[label] += n
                text = new_text

    return text


def anonymize_file_path(path: str) -> str:
    """Strip /Users/<username>/ prefix, keep relative path."""
    return _HOME_RE.sub("", path, count=1)


def scrub_record(record: dict, counts: Counter[str]) -> dict:
    """Scrub a single JSONL record in-place and return it."""
    for field in SCRUB_FIELDS:
        if field in record and isinstance(record[field], str):
            record[field] = scrub_text(record[field], counts)

    if "file_path" in record and isinstance(record["file_path"], str):
        record["file_path"] = anonymize_file_path(record["file_path"])

    return record


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Strip secrets, credentials, and PII from training JSONL files."
    )
    parser.add_argument(
        "-i",
        "--input",
        type=Path,
        default=None,
        help="Input JSONL file (default: stdin)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output JSONL file (default: stdout)",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print redaction summary to stderr",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be redacted without writing output",
    )
    args = parser.parse_args()

    # Input source
    if args.input:
        infile = args.input.open("r", encoding="utf-8")
    else:
        infile = sys.stdin

    # Output destination
    if args.dry_run:
        outfile = None
    elif args.output:
        outfile = args.output.open("w", encoding="utf-8")
    else:
        outfile = sys.stdout

    counts: Counter[str] = Counter()
    total_records = 0
    records_with_redactions = 0

    try:
        for line_num, line in enumerate(infile, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                print(
                    f"WARNING: skipping malformed JSON at line {line_num}",
                    file=sys.stderr,
                )
                continue

            before_total = counts.total()
            scrub_record(record, counts)
            after_total = counts.total()
            total_records += 1

            if after_total > before_total:
                records_with_redactions += 1

            if outfile is not None:
                outfile.write(json.dumps(record, ensure_ascii=False) + "\n")
    finally:
        if args.input and infile is not sys.stdin:
            infile.close()
        if outfile is not None and outfile is not sys.stdout:
            outfile.close()

    if args.report or args.dry_run:
        print("\n--- Scrub Report ---", file=sys.stderr)
        print(f"Total records:           {total_records}", file=sys.stderr)
        print(f"Records with redactions: {records_with_redactions}", file=sys.stderr)
        print(f"Total redactions:        {counts.total()}", file=sys.stderr)
        print(file=sys.stderr)
        if counts:
            max_label_len = max(len(k) for k in counts)
            for label, count in counts.most_common():
                print(
                    f"  {label:<{max_label_len}}  {count}",
                    file=sys.stderr,
                )
        else:
            print("  (no redactions needed)", file=sys.stderr)
        print(file=sys.stderr)


if __name__ == "__main__":
    main()
