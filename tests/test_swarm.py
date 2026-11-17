import copy
import json
import tempfile
import unittest
from pathlib import Path

from triagehive.agents import ReviewerAgent
from triagehive.approvals import apply, load_decisions
from triagehive.audit import verify
from triagehive.report import dashboard, markdown, write_all
from triagehive.swarm import MAX_ALERTS, load_scenario, run, strip_truth

ROOT = Path(__file__).resolve().parent.parent
NIGHT = load_scenario(ROOT / "data" / "scenarios" / "night-shift.json")


class SwarmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = run(NIGHT["alerts"], scenario="night-shift")

    def test_every_verdict_matches_ground_truth(self):
        for alert in NIGHT["alerts"]:
            got = self.result["findings"][alert["alert_id"]]["verdict"]
            want = alert["truth"]["verdict"]
            self.assertEqual(got, want, alert["alert_id"])

    def test_incidents_match_ground_truth(self):
        truth = {}
        for a in NIGHT["alerts"]:
            if a["truth"]["incident"]:
                truth.setdefault(a["truth"]["incident"], set()).add(a["alert_id"])
        got = [set(i["alert_ids"]) for i in self.result["incidents"]]
        self.assertCountEqual(got, list(truth.values()))
        self.assertTrue(all(i["severity"] == "critical" for i in self.result["incidents"]))

    def test_steering_alert_is_escalated_not_obeyed(self):
        f = self.result["findings"]["ALT-3105"]
        self.assertEqual(f["verdict"], "malicious")
        signals = {x["signal"] for x in f["factors"]}
        self.assertIn("steering_text", signals)
        self.assertIn("false_approval_claim", signals)

    def test_truth_is_hidden_from_agents(self):
        self.assertTrue(all("truth" not in a for a in strip_truth(NIGHT["alerts"])))

    def test_every_factor_cites_real_evidence(self):
        self.assertEqual([i for i in self.result["review"] if i["severity"] == "error"], [])

    def test_no_containment_without_approval(self):
        for a in self.result["actions"]:
            if a["tier"] == 0:
                self.assertEqual(a["decision"], "auto_approved")
            else:
                self.assertEqual(a["decision"], "pending", a["action_id"])

    def test_alert_limit(self):
        with self.assertRaises(ValueError):
            run([{"alert_id": f"ALT-{i}", "time": "2026-11-17T00:00:00Z", "rule": "X"} for i in range(MAX_ALERTS + 1)])

    def test_reviewer_catches_hallucinated_target_and_bad_evidence(self):
        r = run(NIGHT["alerts"])
        from triagehive.agents import Action, Finding, Incident
        findings = {k: Finding(**{**v, "factors": []}) for k, v in r["findings"].items()}
        incidents = [Incident(**i) for i in r["incidents"]]
        bogus = Action("ACT-999", incidents[0].incident_id, 1, "isolate_host", "ceo-laptop", "x", "y", True, ["EV-999"])
        issues = ReviewerAgent().review(list(findings), findings, incidents, r["dismissed"], [bogus], set(), set())
        self.assertEqual({i["check"] for i in issues}, {"action"})
        self.assertEqual(len(issues), 2)

    def test_reviewer_flags_coverage_gap(self):
        r = run(NIGHT["alerts"])
        from triagehive.agents import Finding, Incident
        findings = {k: Finding(**{**v, "factors": []}) for k, v in r["findings"].items()}
        incidents = [Incident(**i) for i in r["incidents"]]
        issues = ReviewerAgent().review(list(findings), findings, incidents, r["dismissed"][1:], [], set(), set())
        self.assertEqual([i["check"] for i in issues], ["coverage"])


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.actions = copy.deepcopy(run(NIGHT["alerts"]))["actions"]
        from triagehive.agents import Action
        self.actions = [Action(**a) for a in self.actions]

    def by_id(self, action_id):
        return next(a for a in self.actions if a.action_id == action_id)

    def test_example_file_outcomes(self):
        apply(self.actions, load_decisions(ROOT / "data" / "approvals.example.json"))
        self.assertEqual(self.by_id("ACT-002").decision, "approved")
        self.assertEqual(self.by_id("ACT-004").decision, "pending")      # tier 2, one approver
        self.assertEqual(self.by_id("ACT-005").decision, "approved")     # tier 2, two approvers
        self.assertEqual(self.by_id("ACT-016").decision, "denied")       # a denial wins

    def test_same_person_twice_is_one_approver(self):
        tier2 = next(a for a in self.actions if a.tier == 2)
        apply(self.actions, {tier2.action_id: [{"by": "Lena", "decision": "approve"}, {"by": "lena ", "decision": "approve"}]})
        self.assertEqual(tier2.decision, "pending")

    def test_invalid_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.json"
            path.write_text(json.dumps({"ACT-001": {"by": "", "decision": "approve"}}))
            with self.assertRaises(ValueError):
                load_decisions(path)


class OutputTests(unittest.TestCase):
    def test_files_audit_and_escaping(self):
        alerts = copy.deepcopy(NIGHT["alerts"])
        alerts[0]["detail"] = "<script>alert(1)</script> | **bold** [x](http://e.example)"
        r = run(alerts, scenario="night-shift")
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_all(r, tmp)
            self.assertTrue(all(p.exists() for p in paths.values()))
            ok, message = verify(paths["audit"])
            self.assertTrue(ok, message)
            lines = paths["audit"].read_text().splitlines()
            lines[3] = lines[3].replace('"triage"', '"attacker"')
            paths["audit"].write_text("\n".join(lines) + "\n")
            self.assertFalse(verify(paths["audit"])[0])
        page = dashboard(r)
        self.assertNotIn("<script>", page)
        self.assertIn("default-src 'none'", page)
        self.assertNotIn("<script>", markdown(r))


if __name__ == "__main__":
    unittest.main()
