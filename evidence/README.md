# Evidence

Everything here was produced by running the project.

| File | What it shows |
|---|---|
| `evaluation.md` / `evaluation.json` | Ground-truth evaluation: regression suite (201 scenarios, 2,933 alerts), holdouts, gate |
| `run-output.txt` | CLI run of the showcase night with the MCP server as a subprocess, plus audit verification |
| `sample-run/` | The run's outputs: Markdown report, JSON record, HTML dashboard, hash-chained audit log |
| `test-run.txt` | Verbose output of the 38-test suite |
| `screenshots/` | Dashboard render, GitHub Actions run and repository page |

Reproduce: `python -m triagehive evaluate --seeds 200` and `python -m triagehive run --approvals data/approvals.example.json`.
