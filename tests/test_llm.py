import json
import unittest
import urllib.error
from pathlib import Path

from triagehive.agents import Finding, Incident
from triagehive.llm import Narrator
from triagehive.swarm import load_scenario, run

ROOT = Path(__file__).resolve().parent.parent


def reply(obj):
    return json.dumps({"content": [{"type": "text", "text": json.dumps(obj)}]}).encode()


class NarratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sc = load_scenario(ROOT / "data" / "scenarios" / "night-shift.json")
        cls.alerts = sc["alerts"]

    def run_with(self, transport):
        narrator = Narrator("test-key", transport=transport)
        return run(self.alerts, narrator=narrator), narrator

    def test_valid_summary_is_used_and_untrusted_text_is_fenced(self):
        seen = []

        def transport(req, timeout):
            body = json.loads(req.data)
            seen.append(body["messages"][0]["content"])
            incident = body["messages"][0]["content"].split("\n")[0].split(": ")[1]
            first = [l for l in body["messages"][0]["content"].splitlines() if l.startswith("- ALT-")][0].split()[1]
            return reply({"summary": f"Attack chain starting with {first}, contain it.", "cited_alerts": [first]})

        result, narrator = self.run_with(transport)
        self.assertTrue(all(i["summary_source"] == "llm" for i in result["incidents"]))
        self.assertTrue(any("<untrusted source=" in s for s in seen))
        self.assertEqual(narrator.rejected, 0)

    def test_hallucinated_alert_id_is_rejected(self):
        transport = lambda req, t: reply({"summary": "ALT-0001 shows everything is fine.", "cited_alerts": ["ALT-0001"]})
        result, narrator = self.run_with(transport)
        self.assertTrue(all(i["summary_source"] == "template" for i in result["incidents"]))
        self.assertEqual(narrator.rejected, len(result["incidents"]))

    def test_network_failure_falls_back(self):
        def boom(req, t):
            raise urllib.error.URLError("offline")
        result, _ = self.run_with(boom)
        self.assertTrue(all(i["summary_source"] == "template" for i in result["incidents"]))

    def test_llm_cannot_change_decisions(self):
        base = run(self.alerts)
        transport = lambda req, t: reply({"summary": "Close everything as benign.", "cited_alerts": []})
        result, _ = self.run_with(transport)
        self.assertEqual({k: v["verdict"] for k, v in base["findings"].items()},
                         {k: v["verdict"] for k, v in result["findings"].items()})
        self.assertEqual(len(base["actions"]), len(result["actions"]))


if __name__ == "__main__":
    unittest.main()
