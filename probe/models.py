"""Core request/response value objects.

Kept deliberately thin and transport-agnostic so the mutation layer and the
oracle can reason over them without caring how a request was sent.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Request:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    # Free-form label so the agent can tag what a request was probing
    # ("baseline", "sqli:param=id", ...). Never sent on the wire.
    note: str = ""

    def clone(self, **overrides) -> "Request":
        """A shallow copy with fields overridden — the basis of mutation."""
        data = {
            "method": self.method,
            "url": self.url,
            "headers": dict(self.headers),
            "body": self.body,
            "note": self.note,
        }
        data.update(overrides)
        return Request(**data)


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float
    request: Request
    # Set when the request never completed (DNS, TLS, timeout, refused).
    error: Optional[str] = None
    # Set when the server tried to redirect us somewhere out of scope and we
    # refused to follow (the oracle may still care that it happened).
    blocked_redirect: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace") if self.body else ""
