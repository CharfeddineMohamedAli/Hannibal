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

## Running from the CLI

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python -m probe run \
  --config examples/juice-shop.config.json \
  --goal "Test product search for injection and reflection." \
  --seed "http://localhost:3000/rest/products/search?q=apple" \
  --report findings.md
```

The config is a small JSON file (hosts, headers, identities, rate). See
[`docs/validation.md`](docs/validation.md) for a full first run against a local
OWASP Juice Shop — the right way to check it finds real bugs and avoids false
positives before pointing it anywhere else.

## Running from Python

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

## Human-in-the-loop (default)

The model reasons; a human pulls the trigger. Before any batch of requests is
sent, the tool prints exactly what's queued and waits for your decision —
approve all, none, or the first N. Nothing reaches the network unattended.

```
[approval] probe http://localhost:3000/rest/products/search?q=apple — 9 request(s) queued:
    1. GET http://localhost:3000/rest/products/search?q=apple
    2. GET http://localhost:3000/rest/products/search?q=zq8f...'
    ...
[approval] send which? [a]ll / [n]one / a number N (first N):
```

Pass `--yes` to auto-approve without prompts — only for a lab or scope you own.
The model stays in the reasoning seat (read responses, judge signals, explain
bugs, write the report); you decide what actually gets sent.

## Reporting

Turn a run's findings into a deduplicated Markdown report (severity-ordered, with
a reachability section for each):

```python
findings = agent.run(goal="…")
print(agent.report(program="Example BB", target="api.example-staging.test",
                   when="2026-11-10"))
```

Or render any `list[Finding]` directly with `render_markdown(...)`.

## Authenticated & multi-account (IDOR) testing

Single login — put the token in `required_headers`; it's stamped on every request:

```python
required_headers={"X-Bug-Bounty": "HackerOne-you", "Authorization": "Bearer <token>"}
```

Cross-account (IDOR/BOLA) — define named identities instead, and the agent replays
a request as a different user to check object-level authorization:

```python
ProgramConfig(
    name="...", allowed_hosts=[...],
    required_headers={"X-Bug-Bounty": "HackerOne-you"},   # keep auth OUT of here
    identities={
        "A": {"Authorization": "Bearer <token-A>"},
        "B": {"Authorization": "Bearer <token-B>"},
    },
    default_identity="A",
)
```

Header precedence is request < identity (auth) < required (compliance), so the
identity supplies auth while the required headers can never be dropped. The agent
fetches an object as A, replays the exact request as B, and reports if B gets A's
data instead of being denied.

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
