import json
import unittest
from pathlib import Path

from triagehive.evaluate import evaluate, pair_scores
from triagehive.scenarios import generate

ROOT = Path(__file__).resolve().parent.parent


class EvaluationTests(unittest.TestCase):
    def test_generator_is_deterministic(self):
        self.assertEqual(generate(7), generate(7))
        self.assertNotEqual(generate(7), generate(8))

    def test_generated_truth_is_complete(self):
        for alert in generate(3)["alerts"]:
            self.assertIn(alert["truth"]["verdict"], ("malicious", "benign"))
            self.assertEqual(alert["truth"]["incident"] is None, alert["truth"]["verdict"] == "benign")

    def test_pair_scores(self):
        self.assertEqual(pair_scores({"a": "1", "b": "1", "c": "2"}, {"a": "x", "b": "x", "c": "x"}), (1, 0, 2))

    def test_small_evaluation_passes_gate(self):
        report = evaluate(range(1, 21))
        self.assertTrue(report["gate"]["passed"], report["gate"]["failures"])
        self.assertEqual(report["metrics"]["missed_attacks"], 0)
        self.assertEqual(report["metrics"]["steering_flips"], 0)
        self.assertTrue(all(h["checksum_ok"] for h in report["holdouts"]))

    def test_holdouts_are_not_in_the_generator(self):
        generated = {a["detail"] for s in range(1, 51) for a in generate(s)["alerts"]}
        for name in ("weekend-shift", "holiday-shift"):
            alerts = json.loads((ROOT / "data" / "scenarios" / f"{name}.json").read_text())["alerts"]
            overlap = [a["alert_id"] for a in alerts if a["detail"] in generated]
            self.assertLessEqual(len(overlap), 3, f"{name}: {overlap}")


if __name__ == "__main__":
    unittest.main()
