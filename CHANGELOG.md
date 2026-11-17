# Changelog

## 1.0.0 — 2026-11-17

Complete rewrite as **TriageHive** by Chandu Komme.

- MCP tool server and client written from scratch (JSON-RPC 2.0 over stdio, schema validation, per-agent allowlists,
  call budget), with an in-process transport for fast evaluation.
- Four agents with separate privileges: triage (tools), correlation (entity graph + ATT&CK kill chain), response
  (playbooks with risk tiers), reviewer (coverage, evidence, invented targets, steered dismissals).
- Guardrails: sanitising, steering-text detection, raise-only telemetry signals, change-calendar verification of
  approval claims, spotlighting for the optional LLM narrator.
- Approval gate with tiers 0/1/2 (two distinct approvers for disruptive actions; any denial wins).
- Hash-chained audit log with a verifier; Markdown, JSON and offline HTML dashboard outputs.
- New fictional world, incident memory and three hand-written scenarios; seeded scenario generator with ground truth.
- Evaluation harness with a CI gate, steering probes and checksummed holdouts; 38 unit tests on Python 3.10–3.13.

### Development notes
- The first weekend-shift holdout run dismissed a real attack (unsigned service from /tmp). Fixed with raise-only
  telemetry signals and reopening of dismissed alerts on confirmed-compromised entities; holiday-shift was frozen
  before the fix and run once afterwards (0/7 attacks missed).
- The steering probe first replaced existing notes instead of appending; corrected.
