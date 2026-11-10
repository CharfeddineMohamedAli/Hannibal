"""Per-program rules of engagement, expressed as data.

Nothing in the engine is hard-coded to a particular target. You instantiate a
ProgramConfig from the *verified* scope of whatever program you are authorised to
test, and the engine enforces it. Verify scope against the official program
policy before you fill this in — a config that lists a host is not authorisation
to test it.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProgramConfig:
    name: str
    allowed_hosts: list[str]
    # Identifier/auth headers the program requires on every request.
    required_headers: dict[str, str] = field(default_factory=dict)
    # Sustained ceiling. Keep at or under whatever the program states.
    max_requests_per_sec: float = 5.0
    # Bucket capacity: how many requests may go back-to-back before the
    # sustained rate applies. Default 1 = near-constant spacing (gentlest).
    burst: float = 1.0
    jitter_seconds: float = 0.05
    # Bounty programs commonly warn that in-scope pages link out to production.
    # Off by default: the engine records off-scope redirects but never follows.
    follow_redirects: bool = False
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not self.allowed_hosts:
            raise ValueError("ProgramConfig requires at least one allowed host")
        if self.max_requests_per_sec <= 0:
            raise ValueError("max_requests_per_sec must be > 0")
