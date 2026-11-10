"""The request engine — the deterministic "muscle".

Every request leaving the tool passes through here, and here is where the
program's rules are enforced, in order, before anything touches the network:

    1. scope gate      — refuse any host not on the allowlist
    2. header inject    — stamp the program's required identifier headers
    3. rate limit       — block until under the sustained ceiling
    4. send             — never auto-follow redirects
    5. redirect guard   — surface, but never chase, an off-scope Location

No LLM sits in this path. The agent (the "brain") decides *what* to send and
calls send(); this class guarantees *how* it goes out.
"""
from __future__ import annotations

import time

import httpx

from .config import ProgramConfig
from .models import Request, Response
from .ratelimit import RateLimiter
from .scope import ScopeGuard


class RequestEngine:
    def __init__(self, config: ProgramConfig):
        self.config = config
        self.scope = ScopeGuard(config.allowed_hosts)
        self.limiter = RateLimiter(
            config.max_requests_per_sec,
            config.jitter_seconds,
            burst=config.burst,
        )
        # follow_redirects is always False at the client level; we decide per
        # response whether a redirect is in scope before doing anything with it.
        self._client = httpx.Client(
            follow_redirects=False, timeout=config.timeout_seconds
        )

    def send(self, req: Request) -> Response:
        # 1. Scope gate — before the request can leave the process.
        self.scope.check(req.url)

        # 2. Inject required headers. Program headers win over caller headers so
        #    a mutation can never accidentally strip the identifier the program
        #    requires on every request.
        headers = dict(req.headers)
        headers.update(self.config.required_headers)

        # 3. Rate limit.
        self.limiter.acquire()

        # 4. Send.
        start = time.monotonic()
        try:
            raw = self._client.request(
                req.method, req.url, headers=headers, content=req.body
            )
        except httpx.HTTPError as exc:
            return Response(
                status=0,
                headers={},
                body=b"",
                elapsed_ms=(time.monotonic() - start) * 1000,
                request=req,
                error=str(exc),
            )
        elapsed = (time.monotonic() - start) * 1000

        # 5. Redirect guard. Record an off-scope Location so the oracle can see
        #    it, but never follow it (in-scope pages may link to production).
        blocked = None
        location = raw.headers.get("location")
        if raw.is_redirect and location:
            target = str(raw.url.join(location))
            if not self.scope.allows(target):
                blocked = target

        return Response(
            status=raw.status_code,
            headers=dict(raw.headers),
            body=raw.content,
            elapsed_ms=elapsed,
            request=req,
            blocked_redirect=blocked,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "RequestEngine":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
