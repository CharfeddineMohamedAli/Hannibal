# probe

An agent-driven API security testing tool, for **authorised** testing only
(your own systems, or a bug-bounty program whose scope you have verified and
whose rules you follow).

## Design

Two halves, kept apart on purpose:

- **Muscle** — a deterministic request engine (`probe.engine.RequestEngine`).
  Every request passes through scope enforcement, header injection, and rate
  limiting before it touches the network. No model sits in this path.
- **Brain** (coming next) — an LLM agent that decides *what* to try, reads the
  oracle's structured signals, and picks the next move. It calls the engine as a
  tool; it never fires raw traffic itself.

The split matters: the brain is slow, costly, and non-deterministic, so it
chooses strategy while the muscle does the firing under hard rules.

## What's here so far

| Module | Role |
|--------|------|
| `models.py` | `Request` / `Response` value objects + `clone()` for mutation |
| `scope.py` | `ScopeGuard` — hard host allowlist; refuses off-scope hosts and redirects |
| `ratelimit.py` | token-bucket limiter with jitter |
| `config.py` | `ProgramConfig` — per-program rules of engagement, as data |
| `engine.py` | `RequestEngine` — the compliance-enforcing sender |

Next: mutation layer → oracle (reflection / differential / timing) → agent loop
→ OAST for blind bugs → business-logic reasoning.

## Usage

```python
from probe import ProgramConfig, RequestEngine, Request

config = ProgramConfig(
    name="my-program",
    allowed_hosts=["api.example-staging.test"],
    required_headers={"X-Bug-Bounty": "HackerOne-you"},
    max_requests_per_sec=5.0,
)

with RequestEngine(config) as engine:
    resp = engine.send(Request("GET", "https://api.example-staging.test/health"))
    print(resp.status, resp.elapsed_ms)
```

A request to any host not in `allowed_hosts` raises `ScopeError` before anything
leaves the process.

## Responsible use

This tool only sends traffic you point it at. Point it only at targets you are
authorised to test, verify scope against the program's official policy (not a
summary), stay under the stated rate limit, and follow the program's rules. The
scope allowlist is a safety net, not a substitute for that authorisation.
