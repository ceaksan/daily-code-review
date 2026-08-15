#!/usr/bin/env python3
"""Compare two Ollama model variants (e.g., Q4 vs Q8) on code review tasks.

Sends the same prompts to both models, then uses Claude Opus for blind A/B
scoring. Outputs a comparison report to help choose quantization level.

Usage:
    python compare_quantization.py \
        --model-a my-coder-v1-q4 \
        --model-b my-coder-v1-q8 \
        --samples gold-dataset.jsonl \
        --limit 25 \
        --think off \
        --output comparison-report.json

The --think setting is global: it applies to both models in a run, so a run
cannot compare two thinking levels against each other. To measure the cost of
thinking, do two runs with different --think values and diff the reports.
"""

import argparse
import json
import os
import random
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
CLAUDE_CMD = os.environ.get("CLAUDE_CMD", "claude")

THINK_LEVELS = ("off", "low", "medium", "high")
THINK_TAG_RE = re.compile(r"<think(?:ing)?>[\s\S]*?</think(?:ing)?>", re.IGNORECASE)

JUDGE_PROMPT = """You are judging two code review responses to the same prompt.
You do not know which model produced which response. Score each on three dimensions (1-10):

1. **Correctness**: Is the review accurate? Does it identify real issues?
2. **Detail**: Does it explain WHY something is a problem, not just WHAT?
3. **Actionability**: Can the developer act on this feedback immediately?

## Code Review Prompt
```
{prompt}
```

## Code Context
```
{context}
```

## Response A
```
{response_a}
```

## Response B
```
{response_b}
```

Return ONLY this JSON:
```json
{{
  "a_correctness": 8,
  "a_detail": 7,
  "a_actionability": 8,
  "b_correctness": 7,
  "b_detail": 6,
  "b_actionability": 7,
  "notes": "Brief comparison note"
}}
```"""


def load_samples(path: Path, limit: int) -> list[dict]:
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    if limit > 0:
        records = records[:limit]
    return records


def strip_thinking(text: str) -> str:
    """Drop inline <think> blocks so only the answer reaches the judge."""
    return THINK_TAG_RE.sub("", text).strip()


def query_ollama(
    model: str, prompt: str, think: str = "off", timeout: int = 180
) -> tuple[str, dict]:
    """Return (response_text, metrics). Empty text signals failure."""
    body = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1},
        "think": False if think == "off" else think,
    }
    payload = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"  Ollama error ({model}): {e}", file=sys.stderr)
        return "", {}

    eval_count = data.get("eval_count", 0)
    eval_ns = data.get("eval_duration", 0)
    metrics = {
        "eval_tokens": eval_count,
        "thinking_tokens": len(data.get("thinking", "").split()),
        "total_seconds": round(data.get("total_duration", 0) / 1e9, 2),
        "tok_per_s": round(eval_count / (eval_ns / 1e9), 1) if eval_ns else 0.0,
    }
    return strip_thinking(data.get("response", "")), metrics


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


def build_review_prompt(record: dict) -> str:
    instruction = record.get("instruction", "Review this code change")
    input_code = record.get("input", "")
    return f"{instruction}\n\nCode:\n{input_code[:4000]}"


def main():
    parser = argparse.ArgumentParser(
        description="Compare two Ollama models on code review quality"
    )
    parser.add_argument("--model-a", required=True, help="First Ollama model name")
    parser.add_argument("--model-b", required=True, help="Second Ollama model name")
    parser.add_argument(
        "--samples", required=True, help="Gold Dataset JSONL for test prompts"
    )
    parser.add_argument(
        "--limit", type=int, default=25, help="Number of samples to test (default: 25)"
    )
    parser.add_argument("--output", help="Output JSON report file (default: stdout)")
    parser.add_argument(
        "--think",
        choices=THINK_LEVELS,
        default="off",
        help="Reasoning level applied to BOTH models (default: off). "
        "Compare levels by diffing two runs, not within one run.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Per-model request timeout in seconds (default: 180)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=2.0,
        help="Delay between comparisons in seconds (default: 2.0)",
    )

    args = parser.parse_args()

    samples_path = Path(args.samples)
    if not samples_path.exists():
        print(f"Error: {samples_path} not found", file=sys.stderr)
        sys.exit(1)

    samples = load_samples(samples_path, args.limit)
    print(f"Loaded {len(samples)} samples", file=sys.stderr)
    print(f"Model A: {args.model_a}", file=sys.stderr)
    print(f"Model B: {args.model_b}", file=sys.stderr)
    print(f"Think:   {args.think} (both models)", file=sys.stderr)

    results = []
    a_scores = {"correctness": [], "detail": [], "actionability": []}
    b_scores = {"correctness": [], "detail": [], "actionability": []}
    a_perf = {"tok_per_s": [], "total_seconds": []}
    b_perf = {"tok_per_s": [], "total_seconds": []}

    for i, sample in enumerate(samples):
        print(
            f"\n[{i + 1}/{len(samples)}] Comparing...",
            file=sys.stderr,
            flush=True,
        )

        review_prompt = build_review_prompt(sample)

        print(f"  Querying {args.model_a}...", file=sys.stderr, flush=True)
        resp_a, perf_a = query_ollama(
            args.model_a, review_prompt, args.think, args.timeout
        )
        if not resp_a:
            print("  SKIP (model A failed)", file=sys.stderr)
            continue

        print(f"  Querying {args.model_b}...", file=sys.stderr, flush=True)
        resp_b, perf_b = query_ollama(
            args.model_b, review_prompt, args.think, args.timeout
        )
        if not resp_b:
            print("  SKIP (model B failed)", file=sys.stderr)
            continue

        # Randomize order for blind judging
        swap = random.choice([True, False])
        if swap:
            judge_a, judge_b = resp_b, resp_a
        else:
            judge_a, judge_b = resp_a, resp_b

        judge_prompt = JUDGE_PROMPT.format(
            prompt=sample.get("instruction", "")[:1000],
            context=sample.get("input", "")[:2000],
            response_a=judge_a[:3000],
            response_b=judge_b[:3000],
        )

        print("  Judging with Opus...", file=sys.stderr, flush=True)
        raw_judge = call_claude(judge_prompt)
        scores = parse_json_response(raw_judge)

        if scores is None:
            print("  SKIP (judge failed to parse)", file=sys.stderr)
            continue

        # Unswap scores if needed
        if swap:
            entry = {
                "model_a_correctness": scores.get("b_correctness", 0),
                "model_a_detail": scores.get("b_detail", 0),
                "model_a_actionability": scores.get("b_actionability", 0),
                "model_b_correctness": scores.get("a_correctness", 0),
                "model_b_detail": scores.get("a_detail", 0),
                "model_b_actionability": scores.get("a_actionability", 0),
            }
        else:
            entry = {
                "model_a_correctness": scores.get("a_correctness", 0),
                "model_a_detail": scores.get("a_detail", 0),
                "model_a_actionability": scores.get("a_actionability", 0),
                "model_b_correctness": scores.get("b_correctness", 0),
                "model_b_detail": scores.get("b_detail", 0),
                "model_b_actionability": scores.get("b_actionability", 0),
            }

        entry["notes"] = scores.get("notes", "")
        entry["instruction"] = sample.get("instruction", "")[:100]
        entry["model_a_perf"] = perf_a
        entry["model_b_perf"] = perf_b
        results.append(entry)

        for dim in ("correctness", "detail", "actionability"):
            a_scores[dim].append(entry[f"model_a_{dim}"])
            b_scores[dim].append(entry[f"model_b_{dim}"])
        for key in a_perf:
            a_perf[key].append(perf_a.get(key, 0))
            b_perf[key].append(perf_b.get(key, 0))

        a_avg = sum(entry[f"model_a_{dim}"] for dim in a_scores) / 3
        b_avg = sum(entry[f"model_b_{dim}"] for dim in b_scores) / 3
        print(
            f"  A={a_avg:.1f} ({perf_a.get('tok_per_s', 0):.1f} tok/s)"
            f"  B={b_avg:.1f} ({perf_b.get('tok_per_s', 0):.1f} tok/s)",
            file=sys.stderr,
        )

        if i < len(samples) - 1 and args.delay > 0:
            time.sleep(args.delay)

    if not results:
        print("\nNo results collected.", file=sys.stderr)
        sys.exit(1)

    # Summary
    summary = {
        "model_a": args.model_a,
        "model_b": args.model_b,
        "think": args.think,
        "n": len(results),
    }
    for dim in ("correctness", "detail", "actionability"):
        a_mean = sum(a_scores[dim]) / len(a_scores[dim])
        b_mean = sum(b_scores[dim]) / len(b_scores[dim])
        ratio = (a_mean / b_mean * 100) if b_mean > 0 else 0
        summary[f"a_mean_{dim}"] = round(a_mean, 2)
        summary[f"b_mean_{dim}"] = round(b_mean, 2)
        summary[f"ratio_{dim}"] = round(ratio, 1)

    # Count samples where A < 85% of B
    below_threshold = 0
    for r in results:
        for dim in ("correctness", "detail", "actionability"):
            b_val = r[f"model_b_{dim}"]
            a_val = r[f"model_a_{dim}"]
            if b_val > 0 and (a_val / b_val) < 0.85:
                below_threshold += 1
                break
    summary["samples_a_below_85pct"] = below_threshold
    summary["pct_a_below_85pct"] = round(below_threshold / len(results) * 100, 1)

    for label, perf in (("a", a_perf), ("b", b_perf)):
        for key, values in perf.items():
            summary[f"{label}_mean_{key}"] = (
                round(sum(values) / len(values), 2) if values else 0.0
            )

    report = {"summary": summary, "results": results}

    # Output
    report_json = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(report_json + "\n", encoding="utf-8")
        print(f"\nReport saved to {args.output}", file=sys.stderr)
    else:
        print(report_json)

    # Print summary to stderr
    print("\n--- Summary ---", file=sys.stderr)
    print(f"  Samples: {summary['n']}  Think: {summary['think']}", file=sys.stderr)
    for dim in ("correctness", "detail", "actionability"):
        a = summary[f"a_mean_{dim}"]
        b = summary[f"b_mean_{dim}"]
        r = summary[f"ratio_{dim}"]
        print(f"  {dim:15s}  A={a:.2f}  B={b:.2f}  (A/B={r:.1f}%)", file=sys.stderr)
    print(
        f"  {'speed':15s}  A={summary['a_mean_tok_per_s']:.1f} tok/s"
        f"  B={summary['b_mean_tok_per_s']:.1f} tok/s",
        file=sys.stderr,
    )
    print(
        f"  {'latency':15s}  A={summary['a_mean_total_seconds']:.1f}s"
        f"  B={summary['b_mean_total_seconds']:.1f}s",
        file=sys.stderr,
    )
    print(
        f"  Samples where A < 85% of B: {summary['samples_a_below_85pct']}"
        f" ({summary['pct_a_below_85pct']}%)",
        file=sys.stderr,
    )

    if summary["pct_a_below_85pct"] <= 10:
        print("\n  VERDICT: A (lower quant) is viable.", file=sys.stderr)
    elif summary["pct_a_below_85pct"] <= 25:
        print(
            "\n  VERDICT: Borderline. Consider Q6_K as middle ground.", file=sys.stderr
        )
    else:
        print(
            "\n  VERDICT: A (lower quant) shows significant degradation. Use B.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
