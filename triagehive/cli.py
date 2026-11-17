"""Command-line interface.

Author: Chandu Komme

    triagehive run [SCENARIO] [--out DIR] [--transport stdio|inproc]
                   [--approvals FILE | --interactive] [--llm]
    triagehive evaluate [--seeds N] [--out DIR]      # exit 1 if the gate fails
    triagehive generate --seed N [--out FILE]
    triagehive verify-audit FILE                    # exit 1 if the chain is broken
    triagehive tools [--world DIR]                  # MCP tool server on stdio
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__

__author__ = "Chandu Komme"

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCENARIO = ROOT / "data" / "scenarios" / "night-shift.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="triagehive", description="Multi-agent SOC triage swarm")
    parser.add_argument("--version", action="version", version=f"triagehive {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="triage a scenario")
    run_p.add_argument("scenario", nargs="?", default=str(DEFAULT_SCENARIO))
    run_p.add_argument("--out", default="out")
    run_p.add_argument("--transport", choices=("stdio", "inproc"), default="stdio")
    gate = run_p.add_mutually_exclusive_group()
    gate.add_argument("--approvals", help="JSON file with analyst decisions per action id")
    gate.add_argument("--interactive", action="store_true", help="ask for approvals on the terminal")
    run_p.add_argument("--llm", action="store_true", help="let a language model rewrite summaries (needs ANTHROPIC_API_KEY)")

    ev = sub.add_parser("evaluate", help="score against ground truth and apply the gate")
    ev.add_argument("--seeds", type=int, default=200)
    ev.add_argument("--out", default="reports")

    gen = sub.add_parser("generate", help="write a seeded scenario with ground truth")
    gen.add_argument("--seed", type=int, required=True)
    gen.add_argument("--out")

    va = sub.add_parser("verify-audit", help="verify a hash-chained audit file")
    va.add_argument("path")

    tools = sub.add_parser("tools", help="run the MCP tool server on stdio")
    tools.add_argument("--world")

    args = parser.parse_args(argv)

    if args.command == "tools":
        from .mcp import serve_stdio
        serve_stdio(args.world)
        return 0

    if args.command == "verify-audit":
        from .audit import verify
        ok, message = verify(args.path)
        print(("OK  " if ok else "BROKEN  ") + message)
        return 0 if ok else 1

    if args.command == "generate":
        from .scenarios import generate
        text = json.dumps(generate(args.seed), indent=1)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"wrote {args.out}")
        else:
            print(text)
        return 0

    if args.command == "evaluate":
        from .evaluate import evaluate, markdown
        report = evaluate(range(1, args.seeds + 1))
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        text = markdown(report)
        (out / "evaluation.md").write_text(text, encoding="utf-8")
        print(text)
        return 0 if report["gate"]["passed"] else 1

    # run
    from .approvals import interactive_prompt, load_decisions
    from .llm import Narrator
    from .report import write_all
    from .swarm import load_scenario, run

    scenario = load_scenario(args.scenario)
    decisions = load_decisions(args.approvals) if args.approvals else None
    narrator = None
    if args.llm:
        narrator = Narrator.from_env()
        if narrator is None:
            print("--llm needs ANTHROPIC_API_KEY; using template summaries", file=sys.stderr)
    result = run(scenario["alerts"], transport=args.transport, decisions=decisions,
                 prompt=interactive_prompt if args.interactive else None, narrator=narrator, scenario=scenario["name"])
    paths = write_all(result, args.out)

    errors = [i for i in result["review"] if i["severity"] == "error"]
    print(f"TriageHive {__version__} · {scenario['name']} · run {result['run_id']} · {result['elapsed_ms']} ms")
    print(f"  {result['stats']['alerts']} alerts -> {len(result['incidents'])} incidents, "
          f"{len(result['dismissed'])} dismissed · {result['stats']['tool_calls']} MCP tool calls ({args.transport})")
    for inc in result["incidents"]:
        print(f"  {inc['incident_id']}  {inc['severity']:<8} {inc['status']:<12} {len(inc['alert_ids'])} alerts  "
              f"{' > '.join(inc['tactics'])}")
    counts: dict[str, int] = {}
    for a in result["actions"]:
        counts[a["decision"]] = counts.get(a["decision"], 0) + 1
    print("  actions: " + ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in sorted(counts.items())))
    print(f"  reviewer: {'PASS' if not errors else f'{len(errors)} errors'}")
    for name, path in paths.items():
        print(f"  {name:<9} {path}")
    return 1 if errors else 0
