"""Offline OAST test: canary minting, correlation, and the full agent flow.

No sockets, no network. A FakeEngine simulates a vulnerable target by calling
the canary back the instant it sees one (as a blind SSRF would), so the listener
lights up and the agent can correlate.
"""
from probe.agent import Agent
from probe.llm import FakeLLMClient, LLMResponse, ToolCall
from probe.models import Request, Response
from probe.mutate import mutate
from probe.oast import InMemoryOAST
from probe.payloads import Payload


class CallbackEngine:
    """Echoes nothing useful in the response (blind), but if a request carries a
    known canary, it records a callback on the OAST provider — i.e. the target
    'reached out'."""
    def __init__(self, oast: InMemoryOAST):
        self.oast = oast
        self.sent = []

    def send(self, req, identity=None):
        self.sent.append(req)
        token = self.oast.scan(req.url)
        if token:
            self.oast.record(token, protocol="http", remote_addr="10.0.0.9")
        return Response(status=200, headers={}, body=b"ok", elapsed_ms=40.0, request=req)


def test_mutate_plants_oast_canary():
    oast = InMemoryOAST()
    ssrf = [Payload("{oast}", "ssrf")]   # bare callback URL — the SSRF canary
    req = Request("GET", "https://t.test/fetch?url=x")
    muts = mutate(req, payloads=ssrf, oast=oast)
    assert len(muts) == 1
    m = muts[0]
    assert m.oast_token is not None
    assert m.oast_token in m.request.url     # canary URL carries the token

    # with no provider, an {oast} payload is skipped (nowhere to call back)
    assert mutate(req, payloads=ssrf, oast=None) == []


def test_inmemory_poll_drains():
    oast = InMemoryOAST()
    c = oast.new_canary()
    oast.record(c.token)
    assert [i.token for i in oast.poll()] == [c.token]
    assert oast.poll() == []   # drained


def test_agent_confirms_blind_via_callback():
    oast = InMemoryOAST()
    engine = CallbackEngine(oast)
    ssrf = [Payload("{oast}", "ssrf")]

    script = [
        # 1) probe the url param with the SSRF canary (plants a callback)
        LLMResponse(tool_calls=[ToolCall(
            "t1", "probe_parameter", {"url": "https://t.test/fetch?url=x"})]),
        # 2) poll the listener — the target already called back
        LLMResponse(tool_calls=[ToolCall("t2", "check_oast", {})]),
        # 3) correlate and report the blind SSRF
        LLMResponse(tool_calls=[ToolCall("t3", "report_finding", {
            "title": "Blind SSRF in url parameter",
            "severity": "high",
            "point": "query:url",
            "evidence": "listener received a callback from the target for our canary",
            "reachable_reasoning": "url is user-controlled and fetched server-side; the "
                                   "out-of-band callback proves the request left the server",
            "reproduction": "set url=<your-canary> and watch your listener get a hit",
        })]),
        LLMResponse(text="Blind SSRF confirmed out-of-band. Done."),
    ]
    agent = Agent(engine, FakeLLMClient(script), oast=oast, payloads=ssrf, max_steps=10)
    findings = agent.run(goal="Test the url parameter of /fetch for SSRF.")

    assert len(findings) == 1 and findings[0].severity == "high"
    assert "callback" in findings[0].evidence.lower()


if __name__ == "__main__":
    for fn in [test_mutate_plants_oast_canary, test_inmemory_poll_drains,
               test_agent_confirms_blind_via_callback]:
        fn()
        print("PASS", fn.__name__)
