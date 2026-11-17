"""Mock SOC context MCP server (stdio transport).

Exposes read-only enrichment tools over the official MCP Python SDK. Everything is
backed by data/context_db.json -- no real network calls, no real CMDB, no real TI feed.

Run standalone for a smoke test:
    python src/mcp_server.py            # speaks MCP over stdin/stdout, will look idle

The Enrichment Agent spawns this file as a subprocess (see src/mcp_client.py).

Each lookup reads local sample data. The server supports the CLI's alert batch limit.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:  # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer as ToolServer
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as ToolServer

DATA = Path(__file__).resolve().parent.parent / "data" / "context_db.json"
DB: dict[str, Any] = json.loads(DATA.read_text(encoding="utf-8"))
ALERTS = json.loads((DATA.parent / "alerts.json").read_text(encoding="utf-8"))

mcp = ToolServer("soc-context")

# Hard cap so a looping agent cannot turn the tool layer into a data-exfil firehose.
MAX_RESULTS = 25


@mcp.tool()
def get_asset_info(hostname: str) -> str:
    """Look up asset ownership, environment, criticality and data classification for a host."""
    record = DB["assets"].get(hostname)
    if not record:
        return json.dumps({"hostname": hostname, "found": False})
    return json.dumps({"hostname": hostname, "found": True, **record})


@mcp.tool()
def get_identity_info(principal: str) -> str:
    """Look up whether a user or service account is privileged, its groups, and MFA state."""
    record = DB["identities"].get(principal)
    if not record:
        return json.dumps({"principal": principal, "found": False})
    return json.dumps({"principal": principal, "found": True, **record})


@mcp.tool()
def lookup_threat_intel(indicator: str) -> str:
    """Reputation lookup for an IP address or domain indicator."""
    key = indicator.replace("[.]", ".").replace("hxxp", "http").strip().lower()
    host = (urlsplit(key).hostname or key) if "://" in key else key.split("/", 1)[0]
    record = DB["threat_intel"].get(host)
    if record:
        return json.dumps({"indicator": host, "found": True, **record})
    return json.dumps({"indicator": key, "found": False, "verdict": "unknown"})


@mcp.tool()
def get_rule_history(rule_name: str) -> str:
    """How often a detection rule fired in the last 90 days and its historical true-positive rate."""
    record = DB["alert_history"].get(rule_name)
    if not record:
        return json.dumps({"rule": rule_name, "found": False})
    return json.dumps({"rule": rule_name, "found": True, **record})


@mcp.tool()
def search_related_alerts(principal: str = "", hostname: str = "") -> str:
    """Find other alerts in the current batch touching the same user or host."""
    hits = [
        {"alert_id": a["alert_id"], "rule": a["rule"], "timestamp": a["timestamp"]}
        for a in ALERTS
        if (principal and a.get("user") == principal) or (hostname and a.get("host") == hostname)
    ]
    return json.dumps({"count": len(hits), "alerts": hits[:MAX_RESULTS]})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read-only SOC context MCP server")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    if args.limit is not None:
        ALERTS = ALERTS[:args.limit]
    mcp.run(transport="stdio")
