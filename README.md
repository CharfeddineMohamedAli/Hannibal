# probe

An agent-driven API security testing tool, for **authorised** testing only
(your own systems, or a bug-bounty program whose scope you have verified and
whose rules you follow).

## Design

Two halves, kept apart on purpose:

- **Muscle** — a deterministic request engine (`probe.engine.RequestEngine`).
  Every request passes through scope enforcement, header injection, and rate
  limiting before it touches the network. No model sits in this path.
- **Brain** — an LLM agent (`probe.agent.Agent`) that decides *what* to try,
  reads the oracle's structured signals, and picks the next move. It calls the
  engine through tools; it never fires raw traffic itself, and it treats every
  signal as a hypothesis to corroborate (reachable vs gated) before reporting.

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
| `payloads.py` | curated payload catalogue with canary markers |
| `mutate.py` | injection-point discovery + per-(point,payload) mutations |
| `oracle.py` | detectors → structured `Signal`s (never verdicts) |
| `llm.py` | provider-neutral LLM interface (+ Anthropic adapter, fake client) |
| `tools.py` | the tools the agent calls (`probe_parameter`, `send_request`, `report_finding`) |
| `agent.py` | the loop: methodology + reachable-vs-gated discipline in its system prompt |

Next: OAST (out-of-band) for blind bugs → a target-state model → multi-account
IDOR / business-logic reasoning.

## Running the agent

```python
from probe import ProgramConfig, RequestEngine, Agent, AnthropicClient

config = ProgramConfig(
    name="my-program",
    allowed_hosts=["api.example-staging.test"],
    required_headers={"X-Bug-Bounty": "HackerOne-you"},
    max_requests_per_sec=5.0,
)

with RequestEngine(config) as engine:
    agent = Agent(engine, AnthropicClient())   # needs ANTHROPIC_API_KEY
    findings = agent.run(
        goal="Test the id parameter of /users for injection and reflection.",
        seed_requests=[{"method": "GET", "url": "https://api.example-staging.test/users?id=1"}],
    )
    for f in findings:
        print(f.severity, f.title, "-", f.point)
```

Swap `AnthropicClient()` for any `LLMClient`; `FakeLLMClient` drives the loop in
tests with no API key (see `tests/test_agent.py`).

## Payloads: bring your own

The repo ships only a tiny set of detection probes. For real testing, point the
loader at public payload corpora — the tool stays a loader, not an arsenal:

```python
from probe.payloads import load_payload_file
from probe.mutate import mutate

# download e.g. SecLists / PayloadsAllTheThings, then:
xss = load_payload_file("SecLists/Fuzzing/XSS/XSS-Jhaddix.txt", "reflection")
muts = mutate(request, payloads=xss)
```

Lines with `{m}` get the per-request canary marker; others are sent verbatim.
See `examples/payloads.example.txt` for the format and source links.

## Out-of-band (OAST) for blind bugs

Blind bugs show nothing in the response; you confirm them when the target calls a
listener you run. `probe` ships the **correlation half** only — a self-hostable
listener and canary bookkeeping. The payloads that trigger a callback come from
your own loaded lists, using an `{oast}` placeholder that gets a fresh canary.

```python
from probe import HttpCanaryListener, Agent, RequestEngine
from probe.payloads import load_payload_file

listener = HttpCanaryListener(public_base="http://YOUR.PUBLIC.HOST:8000").start()
ssrf = load_payload_file("ssrf.txt", "ssrf")   # lines containing {oast}

with RequestEngine(config) as engine:
    agent = Agent(engine, AnthropicClient(), oast=listener, payloads=ssrf)
    findings = agent.run(goal="Test /fetch?url= for SSRF.")
listener.stop()
```

The agent plants a canary, then calls `check_oast`; a callback whose token
matches confirms the blind bug out of band. For DNS callbacks, point the same
interface at a self-hosted interactsh.

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
