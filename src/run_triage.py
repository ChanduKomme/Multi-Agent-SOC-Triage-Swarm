"""CLI entrypoint for the SOC triage swarm.

    python src/run_triage.py                  # interactive approval gate
    python src/run_triage.py --auto-approve   # demo/CI mode, no human prompts
    python src/run_triage.py --limit 3        # cheap smoke run over 3 alerts
    python src/run_triage.py --dry-run        # no API calls: MCP + RAG layers only
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from mcp_client import mcp_tool_layer
from orchestrator import DATA, load_alerts, run
from rag_store import IncidentRagStore, alert_to_query


async def dry_run(limit: int | None) -> None:
    """Exercise the plumbing without spending tokens: MCP round-trip + RAG retrieval."""
    rag = IncidentRagStore(DATA / "past_incidents")
    alerts = load_alerts(limit)
    async with mcp_tool_layer(limit=limit) as tools:
        print(f"MCP tools advertised: {[t['name'] for t in tools.tools]}")
        print(await tools.call("lookup_threat_intel", {"indicator": "203.0.113.44"}))
        print(await tools.call("get_identity_info", {"principal": "svc_payments"}))
        print(await tools.call("unlisted_demo_tool", {}))
    for a in alerts:
        hits = rag.retrieve(alert_to_query(a), k=2)
        print(f"{a['alert_id']}: {[(h.doc_id, h.score) for h in hits]}")


def main() -> None:
    try:  # optional: load ANTHROPIC_API_KEY / SOC_MODEL from a local .env
        from dotenv import load_dotenv

        load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    except ImportError:
        pass

    ap = argparse.ArgumentParser(description="Multi-agent SOC triage swarm")
    ap.add_argument("--auto-approve", action="store_true", help="record simulated approvals for demos")
    ap.add_argument("--limit", type=int, default=None, help="only triage the first N alerts")
    ap.add_argument("--dry-run", action="store_true", help="no LLM calls; test MCP + RAG only")
    args = ap.parse_args()
    if args.limit is not None and args.limit < 1:
        ap.error("--limit must be positive")

    if args.dry_run:
        asyncio.run(dry_run(args.limit))
        return
    result = asyncio.run(run(auto_approve=args.auto_approve, limit=args.limit))
    if result["status"] == "needs_review":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
