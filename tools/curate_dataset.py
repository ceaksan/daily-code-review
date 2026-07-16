#!/usr/bin/env python3
"""Dataset curation: Opus-based quality scoring and expert distillation.

Reads approved JSONL training data, scores each record via Claude API,
and outputs a curated Gold Dataset for fine-tuning.

Usage:
    python curate_dataset.py --input approved.jsonl --output gold.jsonl
    python curate_dataset.py --input approved.jsonl --score-only --threshold 7.0
    python curate_dataset.py --input approved.jsonl --rewrite --output gold.jsonl
    python curate_dataset.py --input approved.jsonl --rewrite --domain naming-style --output gold-naming.jsonl
    python curate_dataset.py --input approved.jsonl --score-only --stats
    python curate_dataset.py --input approved.jsonl --dry-run --limit 5
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "system-curation.md"
CLAUDE_CMD = os.environ.get("CLAUDE_CMD", "claude")

GOLD_SCHEMA_FIELDS = ("instruction", "input", "thought", "output", "domain")
DOMAINS = ("naming-style", "security", "error-handling", "architecture", "general")
SCORE_FIELDS = (
    "code_quality",
    "instruction_clarity",
    "generalizability",
    "composite",
    "domain",
    "verdict",
    "reason",
)


def load_system_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def load_records(path: Path) -> list[dict]:
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def call_claude(prompt: str, timeout: int = 120) -> str:
    try:
        result = subprocess.run(
            [CLAUDE_CMD, "-p", prompt, "--output-format", "text"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return ""
    except FileNotFoundError:
        print(f"Error: Claude CLI not found at {CLAUDE_CMD}", file=sys.stderr)
        sys.exit(1)


def parse_json_response(raw: str) -> dict | None:
    import re

    m = re.search(r"```(?:json)?\s*\n(\{[\s\S]*?\})\s*\n```", raw)
    if m:
        try:
            return json.loads(m.group(1))
        except (json.JSONDecodeError, ValueError):
            pass
    try:
        start = raw.index("{")
        end = raw.rindex("}") + 1
        return json.loads(raw[start:end])
    except (ValueError, json.JSONDecodeError):
        return None


def validate_domain(domain: str | None) -> str:
    if domain and domain in DOMAINS:
        return domain
    return "general"


def build_score_prompt(system: str, record: dict) -> str:
    instruction = record.get("instruction", "")
    input_code = record.get("input", "")
    output_code = record.get("output", "")
    return (
        f"{system}\n\n"
        f"## Mode: SCORING\n\n"
        f"Score this training example:\n\n"
        f"### Instruction\n```\n{instruction[:2000]}\n```\n\n"
        f"### Input (original code)\n```\n{input_code[:3000]}\n```\n\n"
        f"### Output (code change)\n```\n{output_code[:3000]}\n```\n\n"
        f"Return ONLY the JSON scoring object."
    )


def build_rewrite_prompt(system: str, record: dict) -> str:
    instruction = record.get("instruction", "")
    input_code = record.get("input", "")
    output_code = record.get("output", "")
    return (
        f"{system}\n\n"
        f"## Mode: REWRITE (Expert Distillation)\n\n"
        f"Rewrite this example into ideal training format with Chain of Thought.\n\n"
        f"### Original Instruction\n```\n{instruction[:2000]}\n```\n\n"
        f"### Original Input\n```\n{input_code[:3000]}\n```\n\n"
        f"### Original Output\n```\n{output_code[:3000]}\n```\n\n"
        f"Return ONLY the JSON object with instruction, input, thought, output, domain fields."
    )


def score_record(system: str, record: dict) -> dict | None:
    prompt = build_score_prompt(system, record)
    raw = call_claude(prompt)
    if not raw:
        return None
    result = parse_json_response(raw)
    if result:
        result["domain"] = validate_domain(result.get("domain"))
    return result


def rewrite_record(system: str, record: dict) -> dict | None:
    prompt = build_rewrite_prompt(system, record)
    raw = call_claude(prompt)
    if not raw:
        return None
    result = parse_json_response(raw)
    if result:
        result["domain"] = validate_domain(result.get("domain"))
    return result


def print_domain_stats(records: list[dict]) -> None:
    counts: dict[str, int] = {d: 0 for d in DOMAINS}
    unclassified = 0
    for r in records:
        curation = r.get("_curation", {})
        domain = curation.get("domain", r.get("domain"))
        if domain and domain in DOMAINS:
            counts[domain] += 1
        else:
            unclassified += 1

    total = sum(counts.values()) + unclassified
    print("\n--- Domain Distribution ---", file=sys.stderr)
    for domain, count in sorted(counts.items(), key=lambda x: -x[1]):
        pct = (count / total * 100) if total > 0 else 0
        bar = "#" * int(pct / 2)
        print(f"  {domain:20s} {count:4d} ({pct:5.1f}%) {bar}", file=sys.stderr)
    if unclassified:
        print(f"  {'(unclassified)':20s} {unclassified:4d}", file=sys.stderr)
    print(f"  {'TOTAL':20s} {total:4d}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Curate training dataset via Claude")
    parser.add_argument("--input", required=True, help="Input JSONL file")
    parser.add_argument("--output", help="Output JSONL file (default: stdout)")
    parser.add_argument(
        "--score-only",
        action="store_true",
        help="Score and filter, don't rewrite",
    )
    parser.add_argument(
        "--rewrite",
        action="store_true",
        help="Rewrite records into Gold Dataset format with Chain of Thought",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=7.0,
        help="Minimum composite score (default: 7.0)",
    )
    parser.add_argument(
        "--domain",
        choices=DOMAINS,
        help="Filter output to a specific domain only",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print domain distribution after processing",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Process only first N records (0 = all)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be processed without calling Claude",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay between API calls in seconds (default: 1.0)",
    )

    args = parser.parse_args()

    if not args.score_only and not args.rewrite:
        args.score_only = True

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} not found", file=sys.stderr)
        sys.exit(1)

    records = load_records(input_path)
    if args.limit > 0:
        records = records[: args.limit]

    print(f"Loaded {len(records)} records from {input_path}", file=sys.stderr)
    if args.domain:
        print(f"Domain filter: {args.domain}", file=sys.stderr)

    if args.dry_run:
        for i, r in enumerate(records):
            inst = (r.get("instruction") or "")[:80]
            ftype = r.get("file_type", "?")
            lines = r.get("change_lines", 0)
            print(f"  [{i + 1}] {ftype} | {lines} lines | {inst}")
        print(f"\nWould process {len(records)} records.", file=sys.stderr)
        return

    system = load_system_prompt()
    scored_records = []
    kept = 0
    discarded = 0
    filtered_by_domain = 0
    errors = 0

    out_file = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout

    try:
        for i, record in enumerate(records):
            print(
                f"[{i + 1}/{len(records)}] Processing...",
                end="",
                file=sys.stderr,
                flush=True,
            )

            if args.score_only:
                result = score_record(system, record)
                if result is None:
                    errors += 1
                    print(" ERROR (no response)", file=sys.stderr)
                    continue

                composite = result.get("composite", 0)
                verdict = result.get("verdict", "discard")
                reason = result.get("reason", "")
                domain = result.get("domain", "general")

                enriched = {**record, "_curation": result}
                scored_records.append(enriched)

                if composite >= args.threshold and verdict == "keep":
                    if args.domain and domain != args.domain:
                        filtered_by_domain += 1
                        print(
                            f" SKIP (domain={domain}, want={args.domain})",
                            file=sys.stderr,
                        )
                        continue
                    out_file.write(json.dumps(enriched, ensure_ascii=False) + "\n")
                    kept += 1
                    print(
                        f" KEEP ({composite:.1f}) [{domain}] {reason}",
                        file=sys.stderr,
                    )
                else:
                    discarded += 1
                    print(f" DISCARD ({composite:.1f}) {reason}", file=sys.stderr)

            elif args.rewrite:
                result = score_record(system, record)
                if result is None:
                    errors += 1
                    print(" ERROR (scoring failed)", file=sys.stderr)
                    continue

                composite = result.get("composite", 0)
                domain = result.get("domain", "general")

                scored_records.append({**record, "_curation": result})

                if composite < args.threshold:
                    discarded += 1
                    print(f" DISCARD ({composite:.1f})", file=sys.stderr)
                    continue

                if args.domain and domain != args.domain:
                    filtered_by_domain += 1
                    print(
                        f" SKIP (domain={domain}, want={args.domain})",
                        file=sys.stderr,
                    )
                    continue

                rewritten = rewrite_record(system, record)
                if rewritten is None:
                    errors += 1
                    print(" ERROR (rewrite failed)", file=sys.stderr)
                    continue

                if all(k in rewritten for k in GOLD_SCHEMA_FIELDS):
                    out_file.write(json.dumps(rewritten, ensure_ascii=False) + "\n")
                    kept += 1
                    print(
                        f" GOLD ({composite:.1f}) [{domain}]",
                        file=sys.stderr,
                    )
                else:
                    missing = [k for k in GOLD_SCHEMA_FIELDS if k not in rewritten]
                    print(f" ERROR (missing fields: {missing})", file=sys.stderr)
                    errors += 1

            if i < len(records) - 1 and args.delay > 0:
                time.sleep(args.delay)

    finally:
        if args.output and out_file is not sys.stdout:
            out_file.close()

    summary = f"\nDone. Kept: {kept} | Discarded: {discarded} | Errors: {errors}"
    if filtered_by_domain:
        summary += f" | Filtered by domain: {filtered_by_domain}"
    print(summary, file=sys.stderr)

    if args.stats and scored_records:
        print_domain_stats(scored_records)


if __name__ == "__main__":
    main()
