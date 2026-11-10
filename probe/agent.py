"""The agent loop — the "brain".

Given a plain-English goal and one or more seed requests, the agent drives the
tools: establish a baseline, probe parameters, read the oracle's structured
signals, corroborate, and record only findings it can justify as reachable. The
LLM chooses strategy; the engine does the firing under its hard rules.

The discipline that matters lives in SYSTEM: a signal is a hypothesis, not a
finding. Before reporting, confirm it (re-run noisy timing, read reflection
context, check the baseline lacked the error) and ask whether an upstream
validator or encoder would gate it — the reachable-vs-gated judgment that keeps
the tool from crying wolf.
"""
from __future__ import annotations

import json

from .engine import RequestEngine
from .llm import LLMClient
from .tools import Finding, Tools

SYSTEM = """\
You are an API security testing agent operating ONLY against targets the user is
authorised to test. The request engine enforces scope, required headers, and a
rate limit; never try to work around it, and don't attempt hosts it refuses.

Method:
1. Establish a baseline with the unmutated request before probing.
2. Use probe_parameter to fan out payloads over a parameter; read the structured
   signals it returns (kind, confidence, evidence). Be economical — this is
   shared, rate-limited infrastructure.
3. A SIGNAL IS A HYPOTHESIS, NOT A FINDING. Before you call report_finding,
   corroborate it:
   - timing: re-run the same request at least once with send_request; trust it
     only if the slowdown is consistent (timing is noisy).
   - reflection: look at the returned context. Unencoded in an HTML/JS sink is a
     real XSS signal; a value that came back HTML-encoded or JSON-escaped is
     probably safe — say so and don't over-report.
   - sql-error / server-error: confirm the baseline did not already contain it.
4. Blind bugs show nothing in the response. If a probe planted an out-of-band
   canary (planted_oast in the result), call check_oast a little later: a
   callback whose token matches confirms the target reached your listener, which
   is strong out-of-band evidence even with an unchanged response.
5. ALWAYS ask: is this input actually attacker-reachable, and could a validator
   or encoder upstream neutralise it before it reaches the sink? If it is likely
   gated, do not report it as a vulnerability (at most note it as info with that
   caveat). Injecting a payload is easy; confirming it reaches the sink is the
   whole job.
6. report_finding only for corroborated issues. Set severity by real impact and
   justify reachability and reproduction. Prefer fewer, solid findings over many
   speculative ones.

When the goal is covered, stop calling tools and give a short summary of what you
tested and what you concluded.
"""


class Agent:
    def __init__(self, engine: RequestEngine, llm: LLMClient, max_steps: int = 24,
                 oast=None, payloads=None):
        self.engine = engine
        self.llm = llm
        self.tools = Tools(engine, oast=oast, payloads=payloads)
        self.max_steps = max_steps
        self.transcript: list[dict] = []

    def run(self, goal: str, seed_requests: list[dict] | None = None) -> list[Finding]:
        intro = goal
        if seed_requests:
            intro += "\n\nSeed requests:\n" + json.dumps(seed_requests, indent=2)
        history: list[dict] = [{"role": "user", "text": intro}]
        schemas = self.tools.schemas()

        for _ in range(self.max_steps):
            resp = self.llm.call(SYSTEM, history, schemas)
            history.append({
                "role": "assistant",
                "text": resp.text,
                "calls": [{"id": c.id, "name": c.name, "args": c.args} for c in resp.tool_calls],
            })
            if resp.done:
                break
            for call in resp.tool_calls:
                result = self.tools.dispatch(call.name, call.args)
                history.append({"role": "tool", "id": call.id, "content": result})

        self.transcript = history
        return self.tools.findings
