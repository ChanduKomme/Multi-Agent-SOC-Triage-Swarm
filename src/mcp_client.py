"""Thin MCP client wrapper: spawns src/mcp_server.py over stdio and adapts its
tool list into Anthropic tool definitions.

This is the trust boundary between the Enrichment Agent (which decides *what* to
look up) and the tool layer (which decides *what is allowed*). Tool results come back
as untrusted data and are passed through guardrails.wrap_untrusted() by the caller.
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = Path(__file__).resolve().parent / "mcp_server.py"

# Allowlist: even if the server advertises more tools, the agent only ever sees these.
ALLOWED_TOOLS = {
    "get_asset_info",
    "get_identity_info",
    "lookup_threat_intel",
    "get_rule_history",
    "search_related_alerts",
}


class McpToolLayer:
    def __init__(self, session: ClientSession, tools: list[dict[str, Any]]):
        self.session = session
        self.tools = tools
        self.call_count = 0

    async def call(self, name: str, arguments: dict[str, Any], max_calls: int = 40) -> str:
        """Invoke one MCP tool. Enforces an allowlist and a per-run call ceiling."""
        if name not in ALLOWED_TOOLS:
            return '{"error":"tool is not allowlisted"}'
        if self.call_count >= max_calls:
            return '{"error":"tool call budget exhausted for this run"}'
        self.call_count += 1
        result = await self.session.call_tool(name, arguments)
        parts = [c.text for c in result.content if getattr(c, "text", None)]
        return "\n".join(parts) or '{"result":"empty"}'


@asynccontextmanager
async def mcp_tool_layer(*, limit: int | None = None):
    """Async context manager yielding a connected McpToolLayer."""
    args = [str(SERVER)]
    if limit is not None:
        args.extend(["--limit", str(limit)])
    params = StdioServerParameters(command=sys.executable, args=args)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listing = await session.list_tools()
            tools = [
                {
                    "name": t.name,
                    "description": (t.description or "").strip(),
                    # mcp 2.x exposes input_schema, mcp 1.x exposes inputSchema
                    "input_schema": getattr(t, "input_schema", None) or t.inputSchema,
                }
                for t in listing.tools
                if t.name in ALLOWED_TOOLS
            ]
            yield McpToolLayer(session, tools)
