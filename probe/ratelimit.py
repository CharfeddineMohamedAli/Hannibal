"""Token-bucket rate limiter.

Caps the sustained request rate (programs often run on shared staging clusters
and set an explicit ceiling) and adds optional jitter so concurrent workers
don't fire in lockstep bursts that momentarily blow past the cap.
"""
from __future__ import annotations

import random
import threading
import time


class RateLimiter:
    def __init__(
        self,
        max_per_sec: float,
        jitter_seconds: float = 0.0,
        burst: float | None = None,
    ):
        if max_per_sec <= 0:
            raise ValueError("max_per_sec must be > 0")
        # `burst` is the bucket capacity: the most requests that can go out
        # back-to-back before the sustained rate takes over. Default 1.0 keeps
        # the tool to near-constant spacing (gentle on shared staging clusters);
        # raise it only if the program tolerates bursts.
        self.rate = float(max_per_sec)
        self.capacity = float(burst) if burst is not None else 1.0
        if self.capacity < 1.0:
            self.capacity = 1.0
        self.tokens = self.capacity
        self.jitter = max(0.0, float(jitter_seconds))
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until a token is available, then (optionally) jitter."""
        while True:
            with self._lock:
                now = time.monotonic()
                self.tokens = min(
                    self.capacity, self.tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    need = 0.0
                else:
                    need = (1.0 - self.tokens) / self.rate
            if need > 0.0:
                time.sleep(need)
                continue
            if self.jitter:
                time.sleep(random.uniform(0.0, self.jitter))
            return
