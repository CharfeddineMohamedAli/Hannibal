"""Human-in-the-loop: the approver gates every send."""
from probe.approve import AutoApprover, ConsoleApprover
from probe.models import Request, Response
from probe.tools import Tools


class RecordingEngine:
    def __init__(self):
        self.sent = []

    def send(self, req, identity=None):
        self.sent.append(req.url)
        return Response(200, {}, req.url.encode(), 10.0, req)


def test_deny_blocks_all_sends():
    engine = RecordingEngine()
    tools = Tools(engine, approver=AutoApprover(allow=False))
    out = tools.dispatch("probe_parameter", {"url": "https://t.test/a?id=1"})
    assert "skipped" in out
    assert engine.sent == []          # nothing left the tool


def test_allow_sends_batch():
    engine = RecordingEngine()
    tools = Tools(engine, approver=AutoApprover(allow=True))
    tools.dispatch("probe_parameter", {"url": "https://t.test/a?id=1", "classes": ["sqli-error"]})
    assert len(engine.sent) >= 2      # baseline + at least one approved mutation


def test_console_first_n():
    # Reader returns "1" -> approve only the first queued request (the baseline).
    engine = RecordingEngine()
    tools = Tools(engine, approver=ConsoleApprover(reader=lambda: "1"))
    out = tools.dispatch("probe_parameter", {"url": "https://t.test/a?id=1", "classes": ["sqli-error"]})
    # baseline approved (first), mutations skipped
    assert len(engine.sent) == 1
    assert '"mutations_sent": 0' in out


def test_console_none_skips_baseline():
    engine = RecordingEngine()
    tools = Tools(engine, approver=ConsoleApprover(reader=lambda: "n"))
    out = tools.dispatch("probe_parameter", {"url": "https://t.test/a?id=1"})
    assert "skipped" in out and engine.sent == []


def test_send_request_gated():
    engine = RecordingEngine()
    tools = Tools(engine, approver=AutoApprover(allow=False))
    out = tools.dispatch("send_request", {"url": "https://t.test/x"})
    assert "skipped" in out and engine.sent == []


if __name__ == "__main__":
    for fn in [test_deny_blocks_all_sends, test_allow_sends_batch, test_console_first_n,
               test_console_none_skips_baseline, test_send_request_gated]:
        fn()
        print("PASS", fn.__name__)
