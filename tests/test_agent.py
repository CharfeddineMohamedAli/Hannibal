"""Offline test of the agent loop: scripted model + fake engine, no network.

Proves the wiring — the model's tool calls are dispatched, the probe fans out
real requests through the engine, the oracle's signals flow back, a finding is
captured, and the loop ends cleanly when the model stops calling tools.
"""
from probe.agent import Agent
from probe.llm import FakeLLMClient, LLMResponse, ToolCall
from probe.models import Response


class FakeEngine:
    """Duck-typed stand-in for RequestEngine. Echoes the request URL in the body,
    so a query-injected marker is 'reflected' and the oracle has something to see."""
    def __init__(self):
        self.sent = []

    def send(self, req):
        self.sent.append(req)
        return Response(status=200, headers={}, body=req.url.encode(),
                        elapsed_ms=50.0, request=req)


def test_agent_runs_tools_and_records_finding():
    engine = FakeEngine()
    script = [
        # 1) model probes the id parameter for reflection
        LLMResponse(tool_calls=[ToolCall(
            "t1", "probe_parameter",
            {"url": "https://api.test/u?id=1", "classes": ["reflection"]},
        )]),
        # 2) model, having seen reflection signals, records a finding
        LLMResponse(tool_calls=[ToolCall(
            "t2", "report_finding",
            {
                "title": "Reflected input in id parameter",
                "severity": "medium",
                "point": "query:id",
                "evidence": "marker reflected unencoded in response body",
                "reachable_reasoning": "id is a user-controlled query param reaching "
                                       "the response with no visible encoding",
                "reproduction": "GET /u?id=<marker>'\"<> and observe it echoed raw",
            },
        )]),
        # 3) model finishes with a summary and no tool calls -> loop ends
        LLMResponse(text="Tested id; reflection corroborated. Done."),
    ]
    llm = FakeLLMClient(script)

    agent = Agent(engine, llm, max_steps=10)
    findings = agent.run(
        goal="Check the id parameter of /u for reflected input.",
        seed_requests=[{"method": "GET", "url": "https://api.test/u?id=1"}],
    )

    # exactly one finding captured, with the model's justification intact
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].point == "query:id"
    assert "reach" in findings[0].reachable_reasoning.lower()

    # the probe actually fanned out: baseline + >=1 mutation went through the engine
    assert len(engine.sent) >= 2

    # the loop consumed the whole script and stopped on the no-tool-call turn
    assert llm.calls_seen == 3

    # the final assistant turn carried the summary text
    assert "Done" in agent.transcript[-1]["text"]


if __name__ == "__main__":
    test_agent_runs_tools_and_records_finding()
    print("PASS test_agent_runs_tools_and_records_finding")
