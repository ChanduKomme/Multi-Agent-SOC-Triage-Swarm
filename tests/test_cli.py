import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from triagehive.cli import main


def run(*args):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(args))
    return code, buf.getvalue()


class CliTests(unittest.TestCase):
    def test_run_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = run("run", "--out", tmp, "--transport", "inproc")
            self.assertEqual(code, 0)
            self.assertIn("2 incidents", out)
            self.assertEqual(run("verify-audit", str(Path(tmp) / "audit.jsonl"))[0], 0)

    def test_generate(self):
        code, out = run("generate", "--seed", "5")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["name"], "generated-5")


if __name__ == "__main__":
    unittest.main()
