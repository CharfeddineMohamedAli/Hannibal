"""Multi-identity: header precedence, identity resolution, and an IDOR flow."""
from probe.agent import Agent
from probe.auth import merge_headers, resolve_identity
from probe.llm import FakeLLMClient, LLMResponse, ToolCall
from probe.models import Response


def test_merge_headers_precedence():
    merged = merge_headers(
        {"Authorization": "req", "X-Keep": "1"},
        {"Authorization": "identity"},          # identity overrides request
        {"Authorization": "required", "X-BB": "id"},  # required overrides all
    )
    assert merged["Authorization"] == "required"
    assert merged["X-Keep"] == "1"
    assert merged["X-BB"] == "id"


def test_resolve_identity():
    ids = {"A": {"Authorization": "Bearer a"}, "B": {"Authorization": "Bearer b"}}
    assert resolve_identity(ids, "B", "A")["Authorization"] == "Bearer b"   # name wins
    assert resolve_identity(ids, None, "A")["Authorization"] == "Bearer a"  # falls to default
    assert resolve_identity(ids, None, None) == {}                         # no identity
    try:
        resolve_identity(ids, "C", None)                                   # unknown
        raise AssertionError("expected ValueError for unknown identity")
    except ValueError:
        pass


class IdorEngine:
    """Simulates broken object-level authz: /orders/42 belongs to account A but
    is returned to ANY identity."""
    def __init__(self):
        self.calls = []

    def send(self, req, identity=None):
        self.calls.append((identity, req.url))
        if req.url.endswith("/orders/42"):
            return Response(200, {}, b'{"id":42,"owner":"A","total":"$999"}', 30.0, req)
        return Response(404, {}, b'{"error":"not found"}', 30.0, req)


def test_agent_finds_idor_across_identities():
    engine = IdorEngine()
    url = "https://t.test/orders/42"
    script = [
        LLMResponse(tool_calls=[ToolCall("1", "send_request", {"url": url, "identity": "A"})]),
        LLMResponse(tool_calls=[ToolCall("2", "send_request", {"url": url, "identity": "B"})]),
        LLMResponse(tool_calls=[ToolCall("3", "report_finding", {
            "title": "IDOR: order 42 readable across accounts",
            "severity": "high",
            "point": "path:/orders/42",
            "evidence": "identity B received account A's order (owner=A) with HTTP 200",
            "reachable_reasoning": "the object id is in the path and no object-level "
                                   "authorization check is applied; B is a separate account",
            "reproduction": "GET /orders/42 with account B's token -> returns account A's order",
        })]),
        LLMResponse(text="IDOR confirmed across accounts. Done."),
    ]
    agent = Agent(engine, FakeLLMClient(script), max_steps=10)
    findings = agent.run(goal="Check /orders/42 for cross-account access.")

    assert len(findings) == 1 and findings[0].severity == "high"
    # both identities were actually used against the same object
    identities_used = {ident for ident, u in engine.calls if u == url}
    assert identities_used == {"A", "B"}


if __name__ == "__main__":
    test_merge_headers_precedence(); print("PASS test_merge_headers_precedence")
    test_resolve_identity(); print("PASS test_resolve_identity")
    test_agent_finds_idor_across_identities(); print("PASS test_agent_finds_idor_across_identities")
