"""
dnm-audit - Daily Code Health Audit CLI

Usage:
    dnm-audit                      # Auto: today's lens, all eligible repos
    dnm-audit --repo dnomia_app    # Specific repo
    dnm-audit --lens architecture  # Specific lens (override schedule)
    dnm-audit --full               # Full scan (ignore skip logic)
    dnm-audit --dry-run            # Show what would be reviewed, don't call LLMs
    dnm-audit --llm claude         # Use only Claude (default: both)
    dnm-audit --llm gemini         # Use only Gemini
    dnm-audit --quiet              # No progress output (for backgrounding)
"""

import argparse
from datetime import datetime

from dnm_audit.config import REPOS, LENS_SCHEDULE, VAULT_DIR, DB_PATH
from dnm_audit import config as _config
from dnm_audit.db import HealthDB
from dnm_audit.scanner import scan_repo
from dnm_audit.reviewer import review_batch, check_ollama_health, LLMChoice
from dnm_audit.reporter import (
    generate_repo_report,
    generate_digest,
    generate_trends_report,
)
from dnm_audit.security import run_security_audit

SEPARATOR_WIDTH = 40


def get_todays_lens() -> str | None:
    weekday = datetime.now().weekday()
    return LENS_SCHEDULE.get(weekday)


def run_repo_audit(
    repo_config,
    db,
    lens,
    llm,
    date_str,
    *,
    quiet=False,
    full=False,
    dry_run=False,
):
    """Run audit pipeline for a single repo. Returns digest entry or None."""
    name = repo_config["name"]
    repo_path = repo_config["path"]

    if not repo_path.exists():
        if not quiet:
            print(f"  {name}: path not found, skipping")
        return None

    if not quiet:
        print(f"\n{'=' * SEPARATOR_WIDTH}")
        print(f"  {name}")
        print(f"{'=' * SEPARATOR_WIDTH}")
        print("  Static scan...")

    scan_results = scan_repo(repo_config)

    current_files = set()
    for sr in scan_results:
        db.upsert_file(name, sr["path"], sr["hash"], sr["complexity"], sr["issues"])
        current_files.add(sr["path"])
    db.cleanup_removed(name, current_files)

    if full:
        candidates = db.get_all_files(name)
    else:
        candidates = db.get_candidates(name, lens=lens)

    if not candidates:
        if not quiet:
            print(f"  No candidates for {lens} lens")
        return None

    if not quiet:
        print(f"  Candidates: {len(candidates)} files")

    if dry_run:
        for c in candidates:
            print(
                f"    {c['path']}"
                f" (complexity={c['complexity']},"
                f" issues={c['static_issues']})"
            )
        return None

    if not quiet:
        print("  Reviewing...")

    all_findings = review_batch(
        repo_config=repo_config,
        candidates=candidates,
        lens=lens,
        llm=llm,
        quiet=quiet,
        db=db,
    )

    for c in candidates:
        file_findings = [
            f
            for f in all_findings
            if f.get("file", "").endswith(c["path"]) or f.get("file") == c["path"]
        ]
        db.mark_reviewed(name, c["path"], lens=lens, findings_count=len(file_findings))

    stats = db.get_repo_stats(name)
    report = generate_repo_report(
        repo_name=name,
        lens=lens,
        findings=all_findings,
        files_reviewed=len(candidates),
        files_total=stats["total_files"],
    )

    report_dir = VAULT_DIR / date_str
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"{name}.md"
    report_path.write_text(report)

    if not quiet:
        print(f"  Report: {report_path}")
        print(f"  Findings: {len(all_findings)}")

    db.insert_history(name, lens, len(all_findings), len(candidates))

    # Track escalations
    escalations = [f for f in all_findings if f.get("_escalation")]
    escalation_count = len(escalations)
    confirmed = len([e for e in escalations if e.get("opus_verdict") == "confirmed"])

    return {
        "repo": name,
        "findings": len(all_findings),
        "critical": len([f for f in all_findings if f.get("severity") == "critical"]),
        "files_reviewed": len(candidates),
        "escalations": escalation_count,
        "escalations_confirmed": confirmed,
    }


def main():
    parser = argparse.ArgumentParser(description="Code Health Audit")
    parser.add_argument("--repo", help="Specific repo name")
    parser.add_argument(
        "--lens",
        help="Override lens"
        " (architecture/duplication/complexity/interfaces/resilience)",
    )
    parser.add_argument(
        "--full", action="store_true", help="Full scan, ignore skip logic"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show plan without executing"
    )
    parser.add_argument(
        "--llm",
        choices=["claude", "gemini", "both", "gemma", "gemma+opus", "all"],
        default="both",
    )
    parser.add_argument(
        "--ollama-check",
        action="store_true",
        help="Check Ollama connectivity and exit",
    )
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument(
        "--trends",
        action="store_true",
        help="Show finding trends for last 14 runs per repo",
    )
    parser.add_argument(
        "--security",
        action="store_true",
        help="Run manual SAST security scan (bypasses lens rotation)",
    )
    args = parser.parse_args()

    repos = REPOS
    if args.repo:
        repos = [r for r in repos if r["name"] == args.repo]
        if not repos:
            print(f"Unknown repo: {args.repo}")
            return

    if args.security:
        if args.llm and args.llm != "both" and not args.quiet:
            print("  Note: --llm ignored; security path is Claude-only.")
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
        db = HealthDB(DB_PATH)
        date_str = datetime.now().strftime("%Y-%m-%d")
        for repo_config in repos:
            run_security_audit(
                repo_config,
                _config,
                db,
                VAULT_DIR,
                date_str,
                quiet=args.quiet,
                dry_run=args.dry_run,
            )
        return

    if args.ollama_check:
        from dnm_audit.config import OLLAMA_BASE_URL, OLLAMA_MODEL

        ok = check_ollama_health()
        if ok:
            print(f"Ollama OK: {OLLAMA_BASE_URL} (model: {OLLAMA_MODEL})")
        else:
            print(f"Ollama unreachable: {OLLAMA_BASE_URL}")
        return

    if args.trends:
        db = HealthDB(DB_PATH)
        for repo_config in repos:
            trends = db.get_trends(repo_config["name"])
            if trends:
                print(generate_trends_report(repo_config["name"], trends))
        return

    lens = args.lens or get_todays_lens()
    if lens is None:
        if not args.quiet:
            print("Weekend. Use --lens to override.")
        return

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    VAULT_DIR.mkdir(parents=True, exist_ok=True)

    db = HealthDB(DB_PATH)

    # Gemma fallback: check Ollama before starting
    effective_llm = args.llm
    if args.llm in ("gemma", "gemma+opus", "all"):
        if not check_ollama_health():
            fallback = {"gemma": "claude", "gemma+opus": "claude", "all": "both"}
            effective_llm = fallback[args.llm]
            if not args.quiet:
                print(f"  Ollama unreachable, falling back to --llm {effective_llm}")

    llm = LLMChoice(effective_llm)

    if not args.quiet:
        repo_names = ", ".join(r["name"] for r in repos)
        print(f"Lens: {lens} | Repos: {repo_names} | LLM: {effective_llm}")

    date_str = datetime.now().strftime("%Y-%m-%d")
    digest_data = []

    for repo_config in repos:
        entry = run_repo_audit(
            repo_config,
            db,
            lens,
            llm,
            date_str,
            quiet=args.quiet,
            full=args.full,
            dry_run=args.dry_run,
        )
        if entry:
            digest_data.append(entry)

    if digest_data and not args.dry_run:
        digest = generate_digest(lens=lens, repo_summaries=digest_data)
        digest_path = VAULT_DIR / date_str / "DIGEST.md"
        digest_path.write_text(digest)
        if not args.quiet:
            print(f"\nDigest: {digest_path}")
