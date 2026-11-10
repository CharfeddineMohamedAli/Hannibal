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
    r"SQLiteException|SQLITE_ERROR|sqlite3\.|near \"[^\"]*\": syntax error|"
    r"SequelizeDatabaseError|Sequelize[A-Za-z]*Error|"
    r"you have an error in your sql|mysql_fetch|"
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


_ENCODED = ("&lt;", "&gt;", "&quot;", "&#39;", "&#x27;", "&amp;", "%3c", "%3e", "\\u003c")


def _reflection_detail(text: str, marker: str, trailing: str):
    """Return (context, raw_intact, encoded) for a reflected marker.

    raw_intact: our breakout characters came back unchanged right after the
    marker (reachable). encoded: they came back escaped (gated — likely safe).
    context: the sink the reflection landed in, which decides how dangerous raw
    reflection is."""
    i = text.find(marker)
    if i == -1:
        return None
    before = text[max(0, i - 80):i].lower()
    after = text[i + len(marker): i + len(marker) + 24]

    # Context from what precedes the reflection.
    last_open = before.rfind("<script")
    if last_open != -1 and before.find("</script", last_open) == -1:
        context = "script"
    else:
        tag = before[before.rfind("<"):]
        context = "attribute" if ("=\"" in tag or "='" in tag) else "html"

    raw_intact = bool(trailing) and (marker + trailing) in text
    encoded = (not raw_intact) and any(e in after.lower() for e in _ENCODED)
    return context, raw_intact, encoded


def _lower_headers(resp: Response) -> dict:
    return {k.lower(): v for k, v in (resp.headers or {}).items()}


def stateless_signals(resp: Response, point: str = "response") -> list[Signal]:
    """Detectors that need no baseline — run on ANY single response (e.g. a
    one-off send_request). Catches the giveaways that stand on their own: a SQL
    error signature, a server stack trace, an /etc/passwd read. Lets the oracle
    flag a bug even when the request wasn't part of a probe batch."""
    out: list[Signal] = []
    if not resp or not resp.ok:
        return out
    text = resp.text
    m = _SQL_ERRORS.search(text)
    if m:
        out.append(Signal("sql-error", 0.75,
                          f"db error signature in response: {m.group(0)!r}", point, "-"))
    sm = _STACK.search(text)
    if sm:
        out.append(Signal("server-error", 0.4,
                          f"server-side error/stack trace: {sm.group(0)!r}", point, "-"))
    if _PASSWD.search(text):
        out.append(Signal("file-read", 0.85,
                          "/etc/passwd signature (root:...:0:0:) in response", point, "-"))
    if resp.status >= 500:
        out.append(Signal("server-500", 0.3,
                          f"HTTP {resp.status} — server error, often an injection symptom",
                          point, "-"))
    return out


def analyze(baseline: Response, mutated: Response, mutation: Mutation) -> list[Signal]:
    signals: list[Signal] = []
    point, pclass = mutation.point, mutation.payload.payload_class
    marker = mutation.marker

    if mutated.error:
        return signals  # a transport error is not a finding

    base_text = baseline.text if baseline and baseline.ok else ""
    mut_text = mutated.text

    # --- Reflection (encoding-aware) -------------------------------------
    if marker in mut_text:
        trailing = mutation.payload.template.split("{m}", 1)[1] if "{m}" in mutation.payload.template else ""
        detail = _reflection_detail(mut_text, marker, trailing)
        context, raw_intact, encoded = detail if detail else ("html", False, False)
        if raw_intact:
            conf = {"script": 0.85, "attribute": 0.7, "html": 0.6}[context]
            ev = f"breakout chars survived UNENCODED in {context} context ({trailing!r})"
        elif encoded:
            conf = 0.15  # gated: our characters came back escaped
            ev = "reflected but breakout chars came back ENCODED — likely gated/safe"
        else:
            conf = 0.2
            ev = "input reflected (no raw breakout chars confirmed here)"
        signals.append(Signal("reflection", conf, ev, point, pclass))

    # --- Reflected into a response header (open redirect / header inject) --
    mut_headers = _lower_headers(mutated)
    for h in ("location", "set-cookie"):
        if marker in mut_headers.get(h, ""):
            signals.append(Signal(
                "header-reflection", 0.5,
                f"input reflected into the {h} header — possible open redirect / "
                f"header injection", point, pclass,
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

    # --- Length differential (boolean-based blind cue) -------------------
    if baseline and baseline.ok and base_text:
        delta = abs(len(mut_text) - len(base_text))
        if delta > 200 and delta > 0.3 * len(base_text):
            signals.append(Signal(
                "diff-length", 0.25,
                f"body size {len(base_text)} -> {len(mut_text)} ({delta} bytes) — "
                f"compare true/false payloads to confirm", point, pclass,
            ))

    return signals
