"""Offline test for the external payload loader."""
import os
import tempfile

from probe.models import Request
from probe.mutate import mutate
from probe.payloads import load_payload_file


SAMPLE = """\
# a comment
{m}<x>

{m}'"<>
plain-no-marker
"""


def test_loader_skips_comments_and_blanks_and_tags_class():
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write(SAMPLE)
        path = fh.name
    try:
        loaded = load_payload_file(path, "reflection")
        templates = [p.template for p in loaded]
        assert templates == ["{m}<x>", "{m}'\"<>", "plain-no-marker"]
        assert all(p.payload_class == "reflection" for p in loaded)
    finally:
        os.unlink(path)


def test_mutate_uses_loaded_payloads():
    loaded = [
        p for p in load_payload_file(_write("{m}<x>\n{m}FOO"), "reflection")
    ]
    req = Request("GET", "https://t.test/a?id=1")
    muts = mutate(req, payloads=loaded)
    # two payloads x one point = two mutations, each carrying a canary marker
    assert len(muts) == 2
    for m in muts:
        assert m.marker in m.request.url
        assert m.point == "query:id"


def _write(content: str) -> str:
    fh = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    fh.write(content)
    fh.close()
    return fh.name


if __name__ == "__main__":
    test_loader_skips_comments_and_blanks_and_tags_class()
    print("PASS test_loader_skips_comments_and_blanks_and_tags_class")
    test_mutate_uses_loaded_payloads()
    print("PASS test_mutate_uses_loaded_payloads")
