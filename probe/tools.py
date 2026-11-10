"""The tools the agent (brain) can call.

Coarse-grained on purpose: `probe_parameter` fans out a baseline plus every
mutation and runs the oracle in one call, so the model reasons over structured
signals instead of sitting in the per-request hot path. `send_request` is for
targeted one-offs (e.g. replaying account B's token against account A's object).
`report_finding` is the only way to record a result — and its schema forces the
model to state why the issue is *reachable* and how to reproduce it, which is the
discipline that separates a real bug from a gated false positive.

Tool results are compact summaries and structured signals — never raw response
bodies dumped whole.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from .engine import RequestEngine
from .models import Request, Response
from .mutate import mutate
from .oracle import analyze, stateless_signals
from .scope import ScopeError


@dataclass
class Finding:
    title: str
    severity: str
    point: str
    evidence: str
    reachable_reasoning: str
    reproduction: str


def _summary(resp: Response, body_chars: int = 240) -> dict:
    snippet = resp.text[:body_chars]
    return {
        "status": resp.status,
        "length": len(resp.body),
        "elapsed_ms": round(resp.elapsed_ms, 1),
        "error": resp.error,
        "blocked_redirect": resp.blocked_redirect,
        "body_snippet": snippet,
    }


def _request_from(args: dict) -> Request:
    body = args.get("body")
    return Request(
        method=args.get("method", "GET"),
        url=args["url"],
        headers=dict(args.get("headers") or {}),
        body=body.encode() if isinstance(body, str) else body,
    )


class Tools:
    def __init__(self, engine: RequestEngine, oast=None, payloads=None, approver=None):
        self.engine = engine
        self.oast = oast            # optional OASTProvider for blind detection
        self.payloads = payloads    # optional loaded payload set (else built-ins)
        self.approver = approver    # optional human-in-the-loop gate
        self.findings: list[Finding] = []

    def _approve(self, label: str, requests: list) -> list:
        """Filter a batch of requests through the approver (all pass if none)."""
        if self.approver is None:
            return requests
        return self.approver.confirm(label, requests)

    # ---- schemas advertised to the model -------------------------------
    def schemas(self) -> list[dict]:
        req_props = {
            "method": {"type": "string", "description": "HTTP method, e.g. GET/POST"},
            "url": {"type": "string", "description": "full in-scope URL"},
            "headers": {"type": "object", "description": "extra request headers"},
            "body": {"type": "string", "description": "raw request body"},
            "identity": {"type": "string", "description": "name of the identity to send "
                                                          "as (for cross-account/IDOR tests); "
                                                          "omit for the default"},
        }
        return [
            {
                "name": "send_request",
                "description": "Send one request and get a compact response summary. "
                               "Use for targeted tests (auth/IDOR replays, re-running a "
                               "timing probe to confirm it).",
                "input_schema": {"type": "object", "properties": req_props, "required": ["url"]},
            },
            {
                "name": "probe_parameter",
                "description": "Send a baseline, then mutate every discovered injection "
                               "point (query + JSON) with the chosen payload classes, run "
                               "the oracle, and return structured signals. One call fans "
                               "out many requests. 'classes' optional: any of reflection, "
                               "sqli-error, sqli-time, ssti, path-traversal.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        **req_props,
                        "classes": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["url"],
                },
            },
            {
                "name": "check_oast",
                "description": "Poll your out-of-band listener for callbacks. A hit "
                               "whose token matches one you planted (see planted_oast "
                               "in a probe result) confirms a blind bug — the target "
                               "reached your listener even though the response showed "
                               "nothing. Call this a little after sending an {oast} "
                               "probe, since callbacks arrive out of band.",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "report_finding",
                "description": "Record a CORROBORATED finding. Only call this after a "
                               "signal has been confirmed (e.g. timing re-run, reflection "
                               "context checked, baseline lacked the error). You must "
                               "justify why the issue is reachable, not gated upstream.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                        "point": {"type": "string", "description": "where, e.g. 'query:id'"},
                        "evidence": {"type": "string"},
                        "reachable_reasoning": {"type": "string",
                                                "description": "why an attacker can reach this; "
                                                               "why it isn't gated by a validator/encoder"},
                        "reproduction": {"type": "string", "description": "exact steps to reproduce"},
                    },
                    "required": ["title", "severity", "point", "evidence",
                                 "reachable_reasoning", "reproduction"],
                },
            },
        ]

    # ---- dispatch ------------------------------------------------------
    def dispatch(self, name: str, args: dict) -> str:
        try:
            if name == "send_request":
                ident = args.get("identity")
                req = _request_from(args)
                if not self._approve(f"send_request ({ident or 'default'})", [req]):
                    return json.dumps({"skipped": "not approved by human"})
                resp = self.engine.send(req, identity=ident)
                out = _summary(resp)
                # Run baseline-free detectors so a one-off send still surfaces a
                # SQL error / stack trace / passwd read as a structured signal.
                out["signals"] = [asdict(s) for s in stateless_signals(resp)]
                return json.dumps(out)

            if name == "probe_parameter":
                ident = args.get("identity")
                base_req = _request_from(args)
                muts = mutate(base_req, classes=args.get("classes"),
                              payloads=self.payloads, oast=self.oast)
                # Human approves the whole batch (baseline + mutations) before any send.
                queued = [base_req] + [m.request for m in muts]
                approved = self._approve(f"probe {base_req.url}", queued)
                approved_set = {id(r) for r in approved}
                if id(base_req) not in approved_set:
                    return json.dumps({"skipped": "baseline not approved; nothing sent"})

                baseline = self.engine.send(base_req, identity=ident)
                signals, planted, sent = [], [], 0
                for m in muts:
                    if id(m.request) not in approved_set:
                        continue
                    sent += 1
                    mutated = self.engine.send(m.request, identity=ident)
                    for s in analyze(baseline, mutated, m):
                        signals.append(asdict(s))
                    if m.oast_token:
                        planted.append({"token": m.oast_token, "point": m.point,
                                        "payload_class": m.payload.payload_class})
                return json.dumps({"baseline": _summary(baseline), "mutations_sent": sent,
                                   "signals": signals, "planted_oast": planted})

            if name == "check_oast":
                if self.oast is None:
                    return json.dumps({"error": "OAST not configured"})
                hits = [{"token": i.token, "protocol": i.protocol, "remote": i.remote_addr}
                        for i in self.oast.poll()]
                return json.dumps({"interactions": hits})

            if name == "report_finding":
                f = Finding(
                    title=args["title"], severity=args["severity"], point=args["point"],
                    evidence=args["evidence"], reachable_reasoning=args["reachable_reasoning"],
                    reproduction=args["reproduction"],
                )
                self.findings.append(f)
                return json.dumps({"recorded": True, "total_findings": len(self.findings)})

            return json.dumps({"error": f"unknown tool: {name}"})
        except ScopeError as e:
            return json.dumps({"error": f"out of scope — refused: {e}"})
        except Exception as e:  # keep the loop alive; the model sees the error
            return json.dumps({"error": f"{type(e).__name__}: {e}"})
