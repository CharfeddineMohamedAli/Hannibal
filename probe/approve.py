"""Human-in-the-loop approval of outgoing requests.

Nothing reaches the network until a human approves it. The agent (the model)
plans what to send; the Approver shows the human exactly which requests are
queued and lets them approve all, none, or the first N. This keeps a person in
the loop on every send — the model reasons, the human pulls the trigger.

Implementations:
  - ConsoleApprover: prints the batch and reads a decision from stdin.
  - AutoApprover: approves (or denies) without asking — for tests and for an
    explicit, deliberate --yes non-interactive run against a lab you own.
"""
from __future__ import annotations

import sys
from abc import ABC, abstractmethod

from .models import Request


class Approver(ABC):
    @abstractmethod
    def confirm(self, label: str, requests: list[Request]) -> list[Request]:
        """Return the subset of `requests` the human approved (possibly empty)."""


class AutoApprover(Approver):
    def __init__(self, allow: bool = True):
        self.allow = allow

    def confirm(self, label: str, requests: list[Request]) -> list[Request]:
        return list(requests) if self.allow else []


class ConsoleApprover(Approver):
    """Interactive gate. Prints the queued requests and asks what to send."""

    def __init__(self, stream=sys.stderr, reader=input):
        self.stream = stream
        self.reader = reader

    def _show(self, label: str, requests: list[Request]) -> None:
        print(f"\n[approval] {label} — {len(requests)} request(s) queued:",
              file=self.stream)
        for i, r in enumerate(requests):
            extra = ""
            if r.body:
                extra = f"  body={r.body[:60]!r}"
            print(f"  {i+1:>3}. {r.method} {r.url}{extra}", file=self.stream)
        print("[approval] send which? [a]ll / [n]one / a number N (first N): ",
              file=self.stream, end="", flush=True)

    def confirm(self, label: str, requests: list[Request]) -> list[Request]:
        if not requests:
            return []
        self._show(label, requests)
        try:
            ans = self.reader().strip().lower()
        except EOFError:
            ans = "n"
        if ans in ("a", "all", "y", "yes", ""):
            return list(requests)
        if ans in ("n", "no", "none"):
            print("[approval] skipped.", file=self.stream)
            return []
        if ans.isdigit():
            n = int(ans)
            print(f"[approval] sending first {n}.", file=self.stream)
            return list(requests[:n])
        print("[approval] unrecognized — skipping.", file=self.stream)
        return []
