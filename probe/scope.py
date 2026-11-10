"""Hard scope enforcement.

This is the single most important safety component: the engine physically cannot
send a request to a host that is not on the allowlist, and will not follow a
redirect that leaves it. Exact-host match by default — a bounty that lists three
hosts means those three, not their subdomains, and "links may point to
production" means off-list targets are refused, not chased.
"""
from __future__ import annotations

from urllib.parse import urlsplit


class ScopeError(Exception):
    """Raised when a URL outside the allowlist is about to be contacted."""


class ScopeGuard:
    def __init__(self, allowed_hosts: list[str]):
        if not allowed_hosts:
            raise ValueError("ScopeGuard needs at least one allowed host")
        self.allowed = {h.strip().lower() for h in allowed_hosts if h.strip()}

    @staticmethod
    def host_of(url: str) -> str:
        return (urlsplit(url).hostname or "").lower()

    def allows(self, url: str) -> bool:
        return self.host_of(url) in self.allowed

    def check(self, url: str) -> None:
        if not self.allows(url):
            host = self.host_of(url) or url
            raise ScopeError(f"refusing out-of-scope host: {host!r}")
