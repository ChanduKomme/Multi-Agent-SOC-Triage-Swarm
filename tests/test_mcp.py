import json
import subprocess
import sys
import unittest

from triagehive.mcp import TOOLS, BudgetExceeded, ToolClient, ToolError, ToolServer

ALLOW = {"triage": set(TOOLS)}


class McpTests(unittest.TestCase):
    def test_handshake_and_listing(self):
        server = ToolServer()
        init = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertIn("tools", init["result"]["capabilities"])
        tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
        self.assertEqual({t["name"] for t in tools}, set(TOOLS))
        self.assertTrue(all(t["annotations"]["readOnlyHint"] for t in tools))
        self.assertIsNone(server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_unknown_method_and_bad_args(self):
        server = ToolServer()
        self.assertEqual(server.handle({"jsonrpc": "2.0", "id": 3, "method": "nope"})["error"]["code"], -32601)
        bad = server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                             "params": {"name": "asset_lookup", "arguments": {"host": "a; rm -rf /"}}})
        self.assertTrue(bad["result"]["isError"])
        extra = server.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                               "params": {"name": "asset_lookup", "arguments": {"host": "dc-01", "x": "1"}}})
        self.assertTrue(extra["result"]["isError"])

    def test_stdio_and_inproc_agree(self):
        results = []
        for transport in ("stdio", "inproc"):
            with ToolClient(transport, allowlists=ALLOW) as client:
                results.append(client.call("triage", "intel_lookup", indicator="203.0.113.66"))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0]["verdict"], "malicious")

    def test_allowlist_and_budget(self):
        with ToolClient(allowlists=ALLOW, budget=2) as client:
            with self.assertRaises(ToolError):
                client.call("response", "asset_lookup", host="dc-01")
            client.call("triage", "asset_lookup", host="dc-01")
            client.call("triage", "asset_lookup", host="dc-01")
            with self.assertRaises(BudgetExceeded):
                client.call("triage", "asset_lookup", host="dc-01")
            self.assertEqual(len(client.denied), 2)
            self.assertEqual([c["evidence_id"] for c in client.calls], ["EV-001", "EV-002"])

    def test_server_survives_garbage_on_stdio(self):
        proc = subprocess.run([sys.executable, "-m", "triagehive", "tools"], input="not json\n" + json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "ping"}) + "\n", capture_output=True, text=True, timeout=20)
        lines = [json.loads(l) for l in proc.stdout.splitlines()]
        self.assertEqual(lines[0]["error"]["code"], -32700)
        self.assertEqual(lines[1]["result"], {})


if __name__ == "__main__":
    unittest.main()
