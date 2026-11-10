"""Out-of-band correlation — the detection half of OAST.

Blind bugs show nothing in the HTTP response; you confirm them by making the
target call a listener YOU run, then matching that callback to the probe that
caused it. This module is that plumbing, and nothing else: it mints unique
canaries, runs a listener you self-host, and correlates callbacks to tokens. The
payloads that actually trigger a callback come from your own loaded lists (see
load_payload_file) via the '{oast}' placeholder — the tool ships none.

Two providers:
  - InMemoryOAST: for tests and local wiring (no sockets).
  - HttpCanaryListener: a real, self-hostable HTTP listener (path-based tokens,
    so no wildcard DNS needed). You run it on a host the target can reach.

DNS-based OAST needs a DNS server and is out of scope here; point the same
interface at a self-hosted interactsh if you need DNS callbacks.
"""
from __future__ import annotations

import secrets
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class Canary:
    token: str
    url: str   # what you plant in a payload; contains the token


@dataclass
class Interaction:
    token: str
    protocol: str          # "http" (this listener) or "dns" (external providers)
    remote_addr: str = ""
    raw: str = ""
    at: float = field(default_factory=time.time)


class OASTProvider(ABC):
    @abstractmethod
    def new_canary(self) -> Canary: ...

    @abstractmethod
    def poll(self) -> list[Interaction]:
        """Return interactions seen since the last poll, and clear them."""


def _new_token() -> str:
    return "oast" + secrets.token_hex(6)


class InMemoryOAST(OASTProvider):
    """No sockets. new_canary mints a token; record() simulates a callback (used
    in tests and for wiring); poll() drains. scan() finds a known token in text,
    so a caller can detect a canary it planted being echoed or requested."""

    def __init__(self, base: str = "http://oast.local"):
        self.base = base.rstrip("/")
        self._tokens: set[str] = set()
        self._pending: list[Interaction] = []
        self._lock = threading.Lock()

    def new_canary(self) -> Canary:
        token = _new_token()
        with self._lock:
            self._tokens.add(token)
        return Canary(token=token, url=f"{self.base}/{token}")

    def record(self, token: str, protocol: str = "http", remote_addr: str = "", raw: str = "") -> None:
        with self._lock:
            self._pending.append(Interaction(token, protocol, remote_addr, raw))

    def scan(self, text: str) -> str | None:
        with self._lock:
            for token in self._tokens:
                if token in text:
                    return token
        return None

    def poll(self) -> list[Interaction]:
        with self._lock:
            out, self._pending = self._pending, []
            return out


class HttpCanaryListener(OASTProvider):
    """A self-hostable HTTP listener. Run it on a host the target can reach; every
    inbound request is recorded, keyed by the first path segment (the token). No
    wildcard DNS needed. `public_base` is how the target addresses you — e.g.
    'http://your.host:8000' — and must match where this actually listens."""

    def __init__(self, public_base: str, host: str = "0.0.0.0", port: int = 8000):
        self.public_base = public_base.rstrip("/")
        self.host = host
        self.port = port
        self._pending: list[Interaction] = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def new_canary(self) -> Canary:
        token = _new_token()
        return Canary(token=token, url=f"{self.public_base}/{token}")

    def _record(self, token: str, remote: str, raw: str) -> None:
        with self._lock:
            self._pending.append(Interaction(token, "http", remote, raw))

    def poll(self) -> list[Interaction]:
        with self._lock:
            out, self._pending = self._pending, []
            return out

    def start(self) -> "HttpCanaryListener":
        listener = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                token = self.path.lstrip("/").split("/", 1)[0].split("?", 1)[0]
                listener._record(token, self.client_address[0], f"{self.command} {self.path}")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = do_POST = do_PUT = do_HEAD = _handle

            def log_message(self, *args):  # silence default stderr logging
                pass

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
