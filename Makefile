# Author: Chandu Komme — TriageHive
PY ?= python3

.PHONY: test run demo evaluate verify clean

test:
	$(PY) -m unittest discover -s tests -v

run:
	$(PY) -m triagehive run --out out

demo:
	$(PY) -m triagehive run --out out --approvals data/approvals.example.json

evaluate:
	$(PY) -m triagehive evaluate --seeds 200 --out reports

verify:
	$(PY) -m triagehive verify-audit out/audit.jsonl

clean:
	rm -rf out reports __pycache__ */__pycache__
