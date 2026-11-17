"""Human approval gate for response actions.

Author: Chandu Komme

Policy by risk tier:

* tier 0 (investigate, open a case) - approved automatically
* tier 1 (reversible containment)   - one analyst approval
* tier 2 (disruptive or critical)   - two approvals from *different* people

Decisions come from an approvals file (for scripted runs and CI), from an
interactive prompt, or from nobody, in which case everything above tier 0 stays
``pending``. A denial from anyone wins. Nothing is ever executed by TriageHive;
an action marked ``approved`` is a change the analyst has signed off.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from .agents import Action

__author__ = "Chandu Komme"

REQUIRED = {0: 0, 1: 1, 2: 2}


def load_decisions(path: str | Path) -> dict[str, list[dict]]:
    """File format: {"ACT-001": [{"by": "alice", "decision": "approve", "reason": "..."}], ...}."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("approvals file must be a JSON object keyed by action id")
    out = {}
    for action_id, entries in data.items():
        entries = entries if isinstance(entries, list) else [entries]
        for e in entries:
            if not isinstance(e, dict) or e.get("decision") not in ("approve", "deny") or not str(e.get("by", "")).strip():
                raise ValueError(f"invalid decision for {action_id}: {e!r}")
        out[action_id] = entries
    return out


def apply(actions: list[Action], decisions: dict[str, list[dict]] | None = None,
          prompt: Callable[[Action], list[dict]] | None = None) -> list[Action]:
    decisions = decisions or {}
    for action in actions:
        need = REQUIRED[action.tier]
        if need == 0:
            action.decision, action.approvers = "auto_approved", ["policy:tier0"]
            continue
        entries = list(decisions.get(action.action_id, []))
        if not entries and prompt is not None:
            entries = prompt(action)
        if any(e["decision"] == "deny" for e in entries):
            action.decision = "denied"
            action.decision_notes = [f"denied by {e['by']}: {e.get('reason', '')}".strip() for e in entries if e["decision"] == "deny"]
            continue
        approvers = sorted({e["by"].strip().lower() for e in entries if e["decision"] == "approve"})
        action.approvers = approvers
        action.decision_notes = [f"{e['by']}: {e.get('reason', '')}".strip(": ") for e in entries]
        if len(approvers) >= need:
            action.decision = "approved"
        else:
            action.decision = "pending"
            if approvers:
                action.decision_notes.append(f"needs {need} distinct approvers, has {len(approvers)}")
    return actions


def interactive_prompt(action: Action) -> list[dict]:  # pragma: no cover - needs a TTY
    print(f"\n[{action.action_id}] tier {action.tier} on {action.incident_id}: {action.description}")
    print(f"    why: {action.rationale}   reversible: {action.reversible}")
    entries = []
    for n in range(REQUIRED[action.tier]):
        answer = input(f"    approver {n + 1} - type 'approve <name>' / 'deny <name>' / Enter to skip: ").strip()
        if not answer:
            break
        verb, _, who = answer.partition(" ")
        if verb in ("approve", "deny") and who:
            entries.append({"by": who, "decision": verb})
            if verb == "deny":
                break
    return entries
