"""Markdown report generation for audit findings."""

import re
from datetime import datetime

SEVERITY_MAP = {
    "critical": "P0",
    "warning": "P1",
    "info": "P2",
}

SEVERITY_ORDER = ["critical", "warning", "info"]


def severity_label(severity: str) -> str:
    return SEVERITY_MAP.get(severity, "P2")


_SECRET_RE = re.compile(r"[A-Za-z0-9_\-+/=]{20,}")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def redact_secrets(text: str) -> str:
    if not isinstance(text, str):
        return ""
    text = _CTRL_RE.sub("", text)
    return _SECRET_RE.sub("***REDACTED***", text)


def final_severity(finding: dict) -> str:
    return finding.get("verify_severity") or finding.get("severity") or "info"


def generate_security_report(
    repo_name, active, capped, refuted, not_scanned, truncation
) -> str:
    today = datetime.now().strftime("%Y-%m-%d")
    lines = [
        f"# {repo_name} — Security Scan",
        "",
        f"**Date**: {today}",
        f"**Active findings**: {len(active)}",
        "",
    ]

    total_capped = (truncation or {}).get("total_capped", 0)
    if total_capped:
        per = (truncation or {}).get("per_class", {})
        detail = ", ".join(f"{k}:{v}" for k, v in sorted(per.items()))
        lines += [
            f"> **Truncation**: {total_capped} finding(s) over the verify budget "
            f"were NOT verified ({detail}). See 'Capped (unverified)'.",
            "",
        ]

    grouped: dict[str, list[dict]] = {}
    unclassified: list[dict] = []
    for f in active:
        sev = final_severity(f)
        if sev in SEVERITY_MAP:
            grouped.setdefault(sev, []).append(f)
        else:
            unclassified.append(f)

    def emit_finding(f):
        title = redact_secrets(str(f.get("title", "")))
        lines.append(f"### {title}")
        lines.append(
            f"**{f.get('file')}:{f.get('line')}** | {f.get('category')} | "
            f"verification: {f.get('verification', 'n/a')} | "
            f"confidence: {f.get('confidence')}"
        )
        if f.get("exploit_path"):
            lines.append(f"- Exploit path: {redact_secrets(str(f['exploit_path']))}")
        lines.append("")
        lines.append(redact_secrets(str(f.get("detail", ""))))
        if f.get("suggestion"):
            lines.append("")
            lines.append(f"**Suggestion**: {redact_secrets(str(f['suggestion']))}")
        lines.append("")

    for sev in SEVERITY_ORDER:
        items = grouped.get(sev)
        if not items:
            continue
        lines.append(f"## {severity_label(sev)} {sev.capitalize()} ({len(items)})")
        lines.append("")
        for f in items:
            emit_finding(f)

    if unclassified:
        lines.append(f"## Unclassified ({len(unclassified)})")
        lines.append("")
        for f in unclassified:
            emit_finding(f)

    if capped:
        lines.append(f"## Capped (unverified) ({len(capped)})")
        lines.append("")
        for f in capped:
            lines.append(
                f"- **{f.get('file')}:{f.get('line')}** | {f.get('category')} | "
                f"{redact_secrets(str(f.get('title', '')))}"
            )
        lines.append("")

    if refuted:
        lines.append(f"## Refuted ({len(refuted)})")
        lines.append("")
        for f in refuted:
            lines.append(
                f"- **{f.get('file')}:{f.get('line')}** | "
                f"{redact_secrets(str(f.get('title', '')))} — "
                f"{redact_secrets(str(f.get('reason', '')))}"
            )
        lines.append("")

    if not_scanned:
        lines.append(f"## Not scanned ({len(not_scanned)})")
        lines.append("")
        for n in not_scanned:
            lines.append(
                f"- {redact_secrets(str(n.get('path', '')))} "
                f"({redact_secrets(str(n.get('reason', '')))})"
            )
        lines.append("")

    if not (active or capped or refuted):
        lines.append("No security findings.")

    return "\n".join(lines) + "\n"


def generate_repo_report(
    repo_name: str,
    lens: str,
    findings: list[dict],
    files_reviewed: int,
    files_total: int,
) -> str:
    today = datetime.now().strftime("%Y-%m-%d")
    lines = [
        f"# {repo_name}",
        "",
        f"**Lens**: {lens}",
        f"**Date**: {today}",
        f"**Files reviewed**: {files_reviewed} / {files_total}",
        f"**Findings**: {len(findings)}",
        "",
    ]

    if not findings:
        lines.append("No findings for this lens. Code looks clean.")
        return "\n".join(lines) + "\n"

    grouped: dict[str, list[dict]] = {}
    for f in findings:
        sev = f.get("severity", "info")
        grouped.setdefault(sev, []).append(f)

    for sev in SEVERITY_ORDER:
        items = grouped.get(sev)
        if not items:
            continue
        label = severity_label(sev)
        heading = f"## {label} {sev.capitalize()} ({len(items)})"
        lines.append(heading)
        lines.append("")

        for item in items:
            title = item["title"]
            source = item.get("source")
            if source:
                title = f"{title} [{source}]"
            lines.append(f"### {title}")
            lines.append(f"**{item['file']}:{item['line']}** | {item['category']}")
            lines.append("")
            lines.append(item["detail"])
            lines.append("")
            lines.append(f"**Suggestion**: {item['suggestion']}")

            # Show Opus verdict for escalated Gemma findings
            if item.get("_escalation"):
                verdict = item.get("opus_verdict", "unknown")
                icon = {"confirmed": "v", "downgraded": ">", "dismissed": "x"}.get(
                    verdict, "?"
                )
                lines.append("")
                lines.append(
                    f"**Opus verdict**: [{icon}] {verdict}"
                    f" ({item.get('opus_severity', '')}) {item.get('opus_detail', '')}"
                )
            lines.append("")

    return "\n".join(lines) + "\n"


def generate_digest(lens: str, repo_summaries: list[dict]) -> str:
    today = datetime.now().strftime("%Y-%m-%d")
    total_files = sum(s["files_reviewed"] for s in repo_summaries)
    total_findings = sum(s["findings"] for s in repo_summaries)
    total_critical = sum(s["critical"] for s in repo_summaries)

    lines = [
        f"# Code Health Audit - {today}",
        "",
        f"**Lens**: {lens}",
        f"**Repos**: {len(repo_summaries)}",
        f"**Files**: {total_files}",
        f"**Findings**: {total_findings}",
        f"**Critical**: {total_critical}",
        "",
        "| Repo | Findings | Critical | Files | Escalations |",
        "| --- | --- | --- | --- | --- |",
    ]

    for s in repo_summaries:
        esc = s.get("escalations", 0)
        esc_confirmed = s.get("escalations_confirmed", 0)
        esc_str = f"{esc_confirmed}/{esc}" if esc > 0 else "-"
        lines.append(
            f"| {s['repo']} | {s['findings']} | {s['critical']}"
            f" | {s['files_reviewed']} | {esc_str} |"
        )

    return "\n".join(lines) + "\n"


def generate_trends_report(repo_name: str, trends: list[dict]) -> str:
    lines = [
        f"# Trends: {repo_name}",
        "",
        "| Date | Lens | Findings | Files |",
        "| --- | --- | --- | --- |",
    ]
    for t in trends:
        date = t["run_date"][:10]
        lines.append(
            f"| {date} | {t['lens']} | {t['findings_count']} | {t['files_reviewed']} |"
        )
    return "\n".join(lines) + "\n"
