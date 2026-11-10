"""Offline CLI tests: config loading, arg parsing, and the no-API-key path.

A full run needs a real model and httpx, so these cover the wiring up to the
point of calling out — config in, graceful exit when no key is set."""
import json
import os
import tempfile

from probe.cli import build_parser, load_config
from probe.cli import main as cli_main
from probe.config import ProgramConfig


def _tmp(content: str) -> str:
    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    fh.write(content)
    fh.close()
    return fh.name


def test_load_config_ok():
    path = _tmp(json.dumps({
        "name": "lab", "allowed_hosts": ["localhost"],
        "max_requests_per_sec": 3, "identities": {"A": {"Authorization": "x"}},
    }))
    cfg = load_config(path)
    assert isinstance(cfg, ProgramConfig)
    assert cfg.allowed_hosts == ["localhost"]
    assert cfg.max_requests_per_sec == 3
    assert "A" in cfg.identities


def test_load_config_rejects_unknown_keys():
    path = _tmp(json.dumps({"name": "x", "allowed_hosts": ["h"], "bogus": 1}))
    try:
        load_config(path)
        raise AssertionError("expected SystemExit on unknown key")
    except SystemExit:
        pass


def test_parser_requires_config_and_goal():
    parser = build_parser()
    ns = parser.parse_args(["run", "--config", "c.json", "--goal", "g", "--seed", "http://h/"])
    assert ns.cmd == "run" and ns.config == "c.json" and ns.seed == ["http://h/"]


def test_run_without_api_key_exits_2():
    path = _tmp(json.dumps({"name": "lab", "allowed_hosts": ["localhost"]}))
    saved = os.environ.pop("ANTHROPIC_API_KEY", None)
    try:
        rc = cli_main(["run", "--config", path, "--goal", "test"])
        assert rc == 2
    finally:
        if saved is not None:
            os.environ["ANTHROPIC_API_KEY"] = saved


if __name__ == "__main__":
    for fn in [test_load_config_ok, test_load_config_rejects_unknown_keys,
               test_parser_requires_config_and_goal, test_run_without_api_key_exits_2]:
        fn()
        print("PASS", fn.__name__)
