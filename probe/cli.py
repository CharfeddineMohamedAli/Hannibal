"""Command-line entrypoint: `python -m probe run --config cfg.json --goal "..."`.

Loads a JSON program config, builds the engine + agent, runs a goal, and prints
(or writes) a Markdown report. Keep it pointed only at systems you're authorised
to test — the scope allowlist in the config is the safety net, not permission.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .config import ProgramConfig


def load_config(path: str) -> ProgramConfig:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    known = {
        "name", "allowed_hosts", "required_headers", "identities",
        "default_identity", "max_requests_per_sec", "burst", "jitter_seconds",
        "follow_redirects", "timeout_seconds",
    }
    unknown = set(data) - known
    if unknown:
        raise SystemExit(f"unknown config keys: {sorted(unknown)}")
    return ProgramConfig(**data)


def _run(args) -> int:
    config = load_config(args.config)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Set ANTHROPIC_API_KEY to run with a real model.", file=sys.stderr)
        return 2

    # Imported here so the no-key path and --help need neither httpx nor the SDK.
    from .agent import Agent
    from .approve import AutoApprover, ConsoleApprover
    from .engine import RequestEngine
    from .llm import AnthropicClient
    from .report import render_markdown

    # Human-in-the-loop by default: every batch of sends is shown and must be
    # approved. --yes auto-approves (use only against a lab/scope you own).
    approver = AutoApprover(allow=True) if args.yes else ConsoleApprover()

    seeds = [{"method": "GET", "url": u} for u in args.seed]
    with RequestEngine(config) as engine:
        agent = Agent(engine, AnthropicClient(model=args.model),
                      max_steps=args.max_steps, verbose=args.verbose, approver=approver)
        findings = agent.run(goal=args.goal, seed_requests=seeds or None)

    print(f"\n{len(findings)} finding(s).\n", file=sys.stderr)
    md = render_markdown(findings, program=config.name,
                         target=", ".join(config.allowed_hosts))
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"Report written to {args.report}", file=sys.stderr)
    else:
        print(md)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="probe", description="Authorised API security testing agent.")
    sub = p.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run the agent against a goal")
    run.add_argument("--config", required=True, help="path to a JSON program config")
    run.add_argument("--goal", required=True, help="plain-English goal")
    run.add_argument("--seed", action="append", default=[],
                     help="seed request URL (repeatable)")
    run.add_argument("--model", default="claude-sonnet-5-5",
                     help="model id (see console.anthropic.com for what your key can use)")
    run.add_argument("--max-steps", type=int, default=24)
    run.add_argument("--verbose", action="store_true",
                     help="print each step: model text, tool calls, and results")
    run.add_argument("--yes", action="store_true",
                     help="auto-approve all sends (no prompts) — only for a lab/scope you own")
    run.add_argument("--report", help="write the Markdown report to this path")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "run":
        return _run(args)
    return 1
