"""Reporting — turn Findings into a clean, deduplicated Markdown report.

Deterministic and dependency-free. Collapses duplicate findings (same title +
location, keeping the highest severity), orders by severity, and renders each
with the fields a reviewer needs: location, evidence, why it is reachable, and
reproduction. The reachability section is first-class on purpose — it is what
separates a report that gets triaged from one that gets closed as noise.
"""
from __future__ import annotations

from .tools import Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _rank(sev: str) -> int:
    return SEVERITY_ORDER.get(sev.lower(), 5)


def dedup(findings: list[Finding]) -> list[Finding]:
    """One finding per (title, location); keep the highest-severity instance."""
    best: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.title.strip().lower(), f.point)
        if key not in best or _rank(f.severity) < _rank(best[key].severity):
            best[key] = f
    return sorted(best.values(), key=lambda f: (_rank(f.severity), f.title.lower()))


def _counts_line(findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1
    parts = [f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts.get(s)]
    return ", ".join(parts) if parts else "none"


def render_markdown(
    findings: list[Finding],
    program: str | None = None,
    target: str | None = None,
    when: str | None = None,
) -> str:
    items = dedup(findings)
    title = "# Security findings" + (f" — {program}" if program else "")
    lines = [title, ""]
    meta = []
    if target:
        meta.append(f"**Target:** {target}")
    if when:
        meta.append(f"**Date:** {when}")
    if meta:
        lines += ["  ".join(meta), ""]

    if not items:
        lines += ["No findings."]
        return "\n".join(lines)

    lines += [f"**Summary:** {len(items)} finding(s) — {_counts_line(items)}", ""]
    lines += ["| # | Severity | Title | Location |", "| - | - | - | - |"]
    for i, f in enumerate(items, 1):
        lines.append(f"| {i} | {f.severity.upper()} | {f.title} | `{f.point}` |")
    lines.append("")

    for i, f in enumerate(items, 1):
        lines += [
            f"## {i}. {f.title}  ({f.severity.upper()})",
            "",
            f"**Location:** `{f.point}`",
            "",
            "**Evidence**",
            "",
            f.evidence,
            "",
            "**Why it's reachable**",
            "",
            f.reachable_reasoning,
            "",
            "**Reproduction**",
            "",
            f.reproduction,
            "",
        ]
    return "\n".join(lines).rstrip() + "\n"
