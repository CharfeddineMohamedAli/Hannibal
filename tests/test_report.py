"""Offline test for the Markdown report renderer."""
from probe.report import dedup, render_markdown
from probe.tools import Finding


def _f(title, sev, point="query:id"):
    return Finding(title=title, severity=sev, point=point, evidence="ev",
                   reachable_reasoning="reachable because", reproduction="do x")


def test_dedup_keeps_highest_severity():
    findings = [_f("SQLi", "low"), _f("SQLi", "high"), _f("XSS", "medium")]
    out = dedup(findings)
    titles = [(f.title, f.severity) for f in out]
    # SQLi collapses to its high instance; sorted high -> medium
    assert titles == [("SQLi", "high"), ("XSS", "medium")]


def test_dedup_distinguishes_by_location():
    findings = [_f("SQLi", "high", "query:id"), _f("SQLi", "high", "query:name")]
    assert len(dedup(findings)) == 2   # same title, different point -> two findings


def test_render_has_sections_and_ordering():
    md = render_markdown(
        [_f("XSS", "medium"), _f("Blind SSRF", "high", "query:url")],
        program="AcmeBB", target="api.test", when="2026-11-10",
    )
    assert "# Security findings — AcmeBB" in md
    assert "**Target:** api.test" in md
    assert "2 finding(s) — 1 high, 1 medium" in md
    # high sorts before medium in both the table and the detail sections
    assert md.index("Blind SSRF") < md.index("XSS")
    # reachability is a first-class section
    assert "**Why it's reachable**" in md


def test_render_empty():
    assert "No findings." in render_markdown([])


if __name__ == "__main__":
    for fn in [test_dedup_keeps_highest_severity, test_dedup_distinguishes_by_location,
               test_render_has_sections_and_ordering, test_render_empty]:
        fn()
        print("PASS", fn.__name__)
