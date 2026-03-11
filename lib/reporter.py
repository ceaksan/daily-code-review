from datetime import datetime

SEVERITY_MAP = {
    "critical": "P0",
    "warning": "P1",
    "info": "P2",
}

SEVERITY_ORDER = ["critical", "warning", "info"]


def severity_label(severity: str) -> str:
    return SEVERITY_MAP.get(severity, "P2")


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
        "| Repo | Findings | Critical | Files |",
        "| --- | --- | --- | --- |",
    ]

    for s in repo_summaries:
        lines.append(
            f"| {s['repo']} | {s['findings']} | {s['critical']} | {s['files_reviewed']} |"
        )

    return "\n".join(lines) + "\n"
