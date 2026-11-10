"""Offline tests: mutation discovery + every oracle detector, no network.

Run: python -m pytest tests/ -q   (or: python tests/test_offline.py)
"""
from probe.models import Request, Response
from probe.mutate import discover_points, mutate
from probe.oracle import analyze


def _resp(body: str, status: int = 200, elapsed_ms: float = 100.0, req=None) -> Response:
    return Response(status=status, headers={}, body=body.encode(), elapsed_ms=elapsed_ms,
                    request=req or Request("GET", "https://t.test/"))


def test_discover_query_and_json_points():
    req = Request("GET", "https://t.test/a?id=1&q=x")
    assert set(discover_points(req)) == {"query:id", "query:q"}

    jreq = Request("POST", "https://t.test/a", headers={"content-type": "application/json"},
                   body=b'{"user_id": 5, "name": "a"}')
    assert set(discover_points(jreq)) == {"json:user_id", "json:name"}


def test_mutation_embeds_marker_in_right_point():
    req = Request("GET", "https://t.test/a?id=1")
    muts = mutate(req, classes=["sqli-error"])
    assert muts, "expected mutations"
    for m in muts:
        assert m.point == "query:id"
        assert m.marker in m.request.url   # canary landed in the target param


def _one(signals, kind):
    return [s for s in signals if s.kind == kind]


def test_reflection_signal_with_context():
    req = Request("GET", "https://t.test/a?q=1")
    m = next(x for x in mutate(req, classes=["reflection"]) if x.payload.template == "{m}'\"<>")
    base = _resp("<html>nothing</html>")
    mutated = _resp(f"<div><script>var x='{m.marker}'\"<></script></div>")
    sig = analyze(base, mutated, m)
    refl = _one(sig, "reflection")
    assert refl and refl[0].confidence >= 0.7   # unencoded, inside <script>


def test_sql_error_signal_only_when_new():
    req = Request("GET", "https://t.test/a?id=1")
    m = next(x for x in mutate(req, classes=["sqli-error"]) if x.payload.template == "{m}'")
    base = _resp("all good")
    mutated = _resp(f"{m.marker} You have an error in your SQL syntax near '''")
    assert _one(analyze(base, mutated, m), "sql-error")
    # Same error already in baseline -> not our doing -> no signal.
    noisy_base = _resp("You have an error in your SQL syntax somewhere")
    assert not _one(analyze(noisy_base, mutated, m), "sql-error")


def test_ssti_eval_signal():
    req = Request("GET", "https://t.test/a?name=1")
    m = next(x for x in mutate(req, classes=["ssti"]) if x.payload.template == "{m}{{7*7}}")
    mutated = _resp(f"Hello {m.marker}49 welcome")
    assert _one(analyze(_resp("Hello"), mutated, m), "ssti-eval")


def test_path_traversal_signal():
    req = Request("GET", "https://t.test/a?file=1")
    m = next(x for x in mutate(req, classes=["path-traversal"])
             if x.payload.payload_class == "path-traversal")
    mutated = _resp("root:x:0:0:root:/root:/bin/bash\n")
    assert _one(analyze(_resp("not found"), mutated, m), "file-read")


def test_timing_signal_needs_real_jump():
    req = Request("GET", "https://t.test/a?id=1")
    m = next(x for x in mutate(req, classes=["sqli-time"]) if "SLEEP" in x.payload.template)
    base = _resp("ok", elapsed_ms=120)
    slow = _resp("ok", elapsed_ms=120 + 4600)      # ~5s jump with 5s sleep
    assert _one(analyze(base, slow, m), "timing")
    fast = _resp("ok", elapsed_ms=140)             # no jump -> no timing signal
    assert not _one(analyze(base, fast, m), "timing")


def test_oracle_stays_silent_on_transport_error():
    req = Request("GET", "https://t.test/a?id=1")
    m = mutate(req, classes=["sqli-error"])[0]
    err = Response(0, {}, b"", 0.0, req, error="connection refused")
    assert analyze(_resp("ok"), err, m) == []


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
