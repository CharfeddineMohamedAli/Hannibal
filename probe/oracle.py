"""The oracle — turns a (baseline, mutated) response pair into structured signals.

Design stance, learned the hard way: the oracle does not announce
vulnerabilities. It emits Signals — "the marker came back unencoded inside a
<script> block", "a SQL error appeared that the baseline didn't have", "the
response took ~5s longer with a 5s sleep payload" — each with evidence and a
heuristic confidence. Whether a signal is a *reachable* bug or a gated
false positive is a judgment the brain makes by corroborating across signals and
re-tests. That separation is the whole point: injection is easy, detection is
hard, and over-claiming detection is how scanners lose trust.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Response
from .mutate import Mutation

# Database error signatures — presence in the mutated response but not the
# baseline is the signal (not the payload echoing back).
_SQL_ERRORS = re.compile(
    r"(SQL syntax|SQLSTATE|ORA-\d{5}|psql:|PG::|"
    r"unclosed quotation mark|quoted string not properly terminated|"
    r"SQLiteException|you have an error in your sql|mysql_fetch|"
    r"org\.hibernate|System\.Data\.SqlClient)",
    re.IGNORECASE,
)

# Generic server-side error / stack-trace signatures.
_STACK = re.compile(
    r"(Traceback \(most recent call last\)|"
    r"\.java:\d+\)|at [\w.$]+\([\w.]+\.(?:java|kt|rb|py):\d+\)|"
    r"Exception in thread|Warning: |Fatal error:)",
)

_PASSWD = re.compile(r"root:.*?:0:0:")


@dataclass
class Signal:
    kind: str          # "reflection", "sql-error", "timing", "diff-status", ...
    confidence: float  # heuristic 0..1 — a prior, not a verdict
    evidence: str      # short, human/LLM readable
    point: str
    payload_class: str


def _context_around(text: str, marker: str) -> str:
    """A tiny window around the marker, so the brain can judge the HTML/JS/JSON
    context a reflection landed in (unencoded <script> vs encoded JSON string)."""
    i = text.find(marker)
    if i == -1:
        return ""
    lo, hi = max(0, i - 40), min(len(text), i + len(marker) + 40)
    return text[lo:hi].replace("\n", " ")


def analyze(baseline: Response, mutated: Response, mutation: Mutation) -> list[Signal]:
    signals: list[Signal] = []
    point, pclass = mutation.point, mutation.payload.payload_class
    marker = mutation.marker

    if mutated.error:
        return signals  # a transport error is not a finding

    base_text = baseline.text if baseline and baseline.ok else ""
    mut_text = mutated.text

    # --- Reflection -------------------------------------------------------
    if marker in mut_text:
        ctx = _context_around(mut_text, marker)
        # Did breakout characters survive alongside the marker?
        raw_special = any(c in ctx for c in "<>\"'") and pclass == "reflection"
        in_script = "<script" in ctx.lower() or "</script" in ctx.lower()
        conf = 0.6 if raw_special else 0.25
        if in_script:
            conf = max(conf, 0.7)
        signals.append(Signal(
            "reflection", conf,
            f"marker reflected; context: …{ctx}…", point, pclass,
        ))

    # --- SQL error signature ---------------------------------------------
    if pclass in ("sqli-error", "reflection"):
        m = _SQL_ERRORS.search(mut_text)
        if m and not _SQL_ERRORS.search(base_text):
            signals.append(Signal(
                "sql-error", 0.75,
                f"db error signature appeared: {m.group(0)!r}", point, pclass,
            ))

    # --- Generic server error / stack trace ------------------------------
    sm = _STACK.search(mut_text)
    if sm and not _STACK.search(base_text):
        signals.append(Signal(
            "server-error", 0.4,
            f"server-side error surfaced: {sm.group(0)!r}", point, pclass,
        ))

    # --- SSTI evaluation --------------------------------------------------
    if pclass == "ssti" and f"{marker}49" in mut_text.replace(" ", ""):
        signals.append(Signal(
            "ssti-eval", 0.85,
            "template expression 7*7 evaluated to 49 next to the marker",
            point, pclass,
        ))

    # --- Path traversal ---------------------------------------------------
    if pclass == "path-traversal" and _PASSWD.search(mut_text) and not _PASSWD.search(base_text):
        signals.append(Signal(
            "file-read", 0.85,
            "/etc/passwd signature (root:...:0:0:) in response", point, pclass,
        ))

    # --- Timing (time-based blind) ---------------------------------------
    if pclass == "sqli-time" and baseline and baseline.ok:
        delay = mutation.payload.expected_delay_ms
        jump = mutated.elapsed_ms - baseline.elapsed_ms
        if delay and jump >= delay * 0.8:
            signals.append(Signal(
                "timing", 0.5,   # modest: timing is noisy, MUST be re-run
                f"response {jump:.0f}ms slower than baseline with a {delay}ms "
                f"sleep payload — re-run to rule out noise before trusting",
                point, pclass,
            ))

    # --- Status differential ---------------------------------------------
    if baseline and baseline.ok and mutated.status != baseline.status:
        signals.append(Signal(
            "diff-status", 0.2,
            f"status {baseline.status} -> {mutated.status}", point, pclass,
        ))

    return signals
