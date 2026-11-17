"""A minimal Model Context Protocol tool server and client, standard library only.

Author: Chandu Komme

The server speaks JSON-RPC 2.0 over stdio, one JSON message per line, which is
the MCP stdio transport. It implements ``initialize``, ``tools/list`` and
``tools/call``. Every tool is read-only and validates its arguments against
the declared input schema before touching data.

The client adds the controls an agent framework should enforce on its side:

* per-agent **allowlists** (the correlation and response agents get no tools)
* a per-run **call budget**, so a confused agent cannot loop forever
* a log of every call, which the orchestrator writes to the audit chain

Two transports share one dispatcher: ``stdio`` spawns the server as a real
subprocess (used by ``triagehive run``), ``inproc`` calls it directly (used by
the evaluation harness, which runs hundreds of scenarios).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Any, Callable

from . import __version__
from .world import World

__author__ = "Chandu Komme"

PROTOCOL_VERSION = "2025-06-18"
_SAFE = re.compile(r"^[\w.:/@\-]{1,128}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _schema(**props: str) -> dict:
    return {"type": "object", "properties": {k: {"type": "string", "description": v} for k, v in props.items()},
            "required": list(props), "additionalProperties": False}


TOOLS: dict[str, dict] = {
    "asset_lookup": {"description": "Asset inventory record for a hostname or cloud account.",
                     "inputSchema": _schema(host="hostname or account")},
    "identity_lookup": {"description": "Directory record for a user, service or cloud principal.",
                        "inputSchema": _schema(principal="principal name")},
    "intel_lookup": {"description": "Threat-intel verdict for an IP, domain or SHA-256.",
                     "inputSchema": _schema(indicator="IP, domain or hash")},
    "geo_lookup": {"description": "Country, ASN and hosting flag for an IP address.",
                   "inputSchema": _schema(ip="IPv4 address")},
    "rule_stats": {"description": "90-day history and false-positive rate of a detection rule.",
                   "inputSchema": _schema(rule="rule id")},
    "change_calendar": {"description": "Approved change covering a target at a given UTC time, if any.",
                        "inputSchema": _schema(target="host or principal", at="UTC time, YYYY-MM-DDTHH:MM:SSZ")},
}


class ToolError(Exception):
    """Raised for anything a tool call must not be allowed to do."""


def _validate(name: str, args: Any) -> dict:
    if name not in TOOLS:
        raise ToolError(f"unknown tool {name!r}")
    schema = TOOLS[name]["inputSchema"]
    if not isinstance(args, dict):
        raise ToolError("arguments must be an object")
    extra = set(args) - set(schema["properties"])
    missing = set(schema["required"]) - set(args)
    if extra or missing:
        raise ToolError(f"bad arguments: missing={sorted(missing)} unexpected={sorted(extra)}")
    for key, value in args.items():
        pattern = _TIME if key == "at" else _SAFE
        if not isinstance(value, str) or not pattern.match(value):
            raise ToolError(f"argument {key!r} has an invalid value")
    return args


class ToolServer:
    """The dispatcher. Only this class reads the world data."""

    def __init__(self, world: World | None = None) -> None:
        w = world or World()
        self.impl: dict[str, Callable[..., dict]] = {
            "asset_lookup": lambda host: w.asset(host),
            "identity_lookup": lambda principal: w.identity(principal),
            "intel_lookup": lambda indicator: w.threat_intel(indicator),
            "geo_lookup": lambda ip: w.geolocate(ip),
            "rule_stats": lambda rule: w.rule(rule),
            "change_calendar": lambda target, at: w.change_window(target, at),
        }

    def handle(self, message: dict) -> dict | None:
        """Handle one JSON-RPC message; notifications return None."""
        method, msg_id = message.get("method"), message.get("id")
        if msg_id is None:
            return None
        try:
            if method == "initialize":
                result = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {"name": "triagehive-tools", "version": __version__}}
            elif method == "tools/list":
                result = {"tools": [{"name": n, **spec, "annotations": {"readOnlyHint": True}}
                                    for n, spec in TOOLS.items()]}
            elif method == "tools/call":
                params = message.get("params") or {}
                name = params.get("name")
                try:
                    args = _validate(name, params.get("arguments"))
                    data = self.impl[name](**args)
                    result = {"content": [{"type": "text", "text": json.dumps(data)}],
                              "structuredContent": data, "isError": False}
                except ToolError as err:
                    result = {"content": [{"type": "text", "text": str(err)}], "isError": True}
            elif method == "ping":
                result = {}
            else:
                return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"unknown method {method}"}}
        except Exception as err:  # never let a bad request kill the server
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32603, "message": type(err).__name__}}
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def serve_stdio(world_dir: str | None = None) -> None:
    server = ToolServer(World(world_dir) if world_dir else None)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            reply = server.handle(message)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


class BudgetExceeded(ToolError):
    pass


class ToolClient:
    def __init__(self, transport: str = "inproc", budget: int = 200, world_dir: str | None = None,
                 allowlists: dict[str, set[str]] | None = None) -> None:
        self.transport = transport
        self.budget = budget
        self.calls: list[dict] = []
        self.denied: list[dict] = []
        self.allowlists = allowlists if allowlists is not None else {}
        self._next_id = 0
        if transport == "inproc":
            self._server = ToolServer(World(world_dir) if world_dir else None)
            self._proc = None
        elif transport == "stdio":
            cmd = [sys.executable, "-m", "triagehive", "tools"] + (["--world", world_dir] if world_dir else [])
            self._proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        else:
            raise ValueError("transport must be 'inproc' or 'stdio'")
        info = self._rpc("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                        "clientInfo": {"name": "triagehive-swarm", "version": __version__}})
        self.server_info = info["serverInfo"]
        self._notify("notifications/initialized")
        self.tools = [t["name"] for t in self._rpc("tools/list", {})["tools"]]

    def _send(self, message: dict) -> dict | None:
        if self._proc is None:
            return self._server.handle(json.loads(json.dumps(message)))
        self._proc.stdin.write(json.dumps(message) + "\n")
        self._proc.stdin.flush()
        if "id" not in message:
            return None
        line = self._proc.stdout.readline()
        if not line:
            raise ToolError("tool server exited")
        return json.loads(line)

    def _notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def _rpc(self, method: str, params: dict) -> dict:
        self._next_id += 1
        reply = self._send({"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params})
        if "error" in reply:
            raise ToolError(reply["error"]["message"])
        return reply["result"]

    def call(self, agent: str, name: str, **arguments: str) -> dict:
        allowed = self.allowlists.get(agent, set())
        if name not in allowed:
            self.denied.append({"agent": agent, "tool": name, "reason": "not on allowlist"})
            raise ToolError(f"agent {agent!r} may not call {name!r}")
        if len(self.calls) >= self.budget:
            self.denied.append({"agent": agent, "tool": name, "reason": "budget exhausted"})
            raise BudgetExceeded(f"tool budget of {self.budget} calls exhausted")
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        evidence_id = f"EV-{len(self.calls) + 1:03d}"
        record = {"evidence_id": evidence_id, "agent": agent, "tool": name, "arguments": arguments,
                  "error": result.get("isError", False)}
        self.calls.append(record)
        if result.get("isError"):
            raise ToolError(result["content"][0]["text"])
        return {"evidence_id": evidence_id, **result["structuredContent"]}

    def close(self) -> None:
        if self._proc is not None:
            self._proc.stdin.close()
            self._proc.wait(timeout=5)
            self._proc.stdout.close()
            self._proc = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
