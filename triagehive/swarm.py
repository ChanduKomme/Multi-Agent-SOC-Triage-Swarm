"""The orchestrator: runs the four agents in order and records everything.

Author: Chandu Komme

    alerts -> TriageAgent (tools) -> CorrelationAgent -> ResponseAgent
           -> ReviewerAgent -> approval gate -> report + hash-chained audit

The orchestrator also enforces run-level limits (maximum alerts, tool-call
budget) and strips ground-truth labels from scenario files so no agent can see
them.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from . import __version__
from .agents import CorrelationAgent, ReviewerAgent, ResponseAgent, TriageAgent
from .approvals import apply
from .audit import AuditLog
from .mcp import ToolClient
from .memory import IncidentMemory

__author__ = "Chandu Komme"

MAX_ALERTS = 500


def load_scenario(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    alerts = data["alerts"] if isinstance(data, dict) else data
    return {"name": data.get("name", Path(path).stem) if isinstance(data, dict) else Path(path).stem,
            "description": data.get("description", "") if isinstance(data, dict) else "", "alerts": alerts}


def strip_truth(alerts: list[dict]) -> list[dict]:
    return [{k: v for k, v in a.items() if k != "truth"} for a in alerts]


def run(alerts: list[dict], *, transport: str = "inproc", decisions: dict | None = None, prompt=None,
        narrator=None, memory: IncidentMemory | None = None, tool_budget: int | None = None,
        scenario: str = "adhoc") -> dict:
    started = time.perf_counter()
    alerts = strip_truth(alerts)
    if len(alerts) > MAX_ALERTS:
        raise ValueError(f"refusing to triage {len(alerts)} alerts in one run (limit {MAX_ALERTS})")
    run_id = hashlib.sha256(json.dumps(alerts, sort_keys=True).encode()).hexdigest()[:12]
    audit = AuditLog(run_id)
    audit.add("orchestrator", "run_started", {"scenario": scenario, "alerts": len(alerts), "version": __version__,
                                              "transport": transport})

    memory = memory or IncidentMemory()
    triage = TriageAgent.__new__(TriageAgent)
    allow = {TriageAgent.name: TriageAgent.tools}  # every other agent gets no tools
    budget = tool_budget if tool_budget is not None else 12 * len(alerts) + 10
    with ToolClient(transport, budget=budget, allowlists=allow) as client:
        triage.__init__(client, memory)
        findings = {}
        for raw in alerts:
            before = len(client.calls)
            finding = triage.assess(raw)
            findings[finding.alert_id] = finding
            for call in client.calls[before:]:
                audit.add("triage", "tool_call", call)
            audit.add("triage", "finding", {"alert_id": finding.alert_id, "verdict": finding.verdict,
                                            "probability": finding.probability, "severity": finding.severity,
                                            "factors": [f.signal for f in finding.factors],
                                            "guard": [g["signal"] for g in finding.guard]})
        tool_calls, denied, server = list(client.calls), list(client.denied), client.server_info

    incidents, dismissed = CorrelationAgent().correlate(list(findings.values()))
    for inc in incidents:
        audit.add("correlation", "incident", {"incident_id": inc.incident_id, "alerts": inc.alert_ids,
                                              "severity": inc.severity, "links": inc.links})
    audit.add("correlation", "dismissed", {"alerts": dismissed})

    if narrator is not None:
        for inc in incidents:
            text = narrator.summarise(inc, findings)
            if text:
                inc.summary, inc.summary_source = text, "llm"
            audit.add("narrator", "summary", {"incident_id": inc.incident_id, "source": inc.summary_source})

    actions = ResponseAgent().plan(incidents, findings)
    for a in actions:
        audit.add("response", "proposed_action", {"action_id": a.action_id, "incident": a.incident_id,
                                                  "tier": a.tier, "kind": a.kind, "target": a.target})

    evidence_ids = {c["evidence_id"] for c in tool_calls}
    memory_ids = {d["id"] for d in memory.docs}
    issues = ReviewerAgent().review([a.get("alert_id", "unknown") for a in alerts], findings, incidents, dismissed,
                                    actions, evidence_ids, memory_ids)
    audit.add("reviewer", "review", {"issues": issues})

    apply(actions, decisions, prompt)
    for a in actions:
        audit.add("approval_gate", "decision", {"action_id": a.action_id, "decision": a.decision, "approvers": a.approvers})

    elapsed = round((time.perf_counter() - started) * 1000, 1)
    audit.add("orchestrator", "run_finished", {"incidents": len(incidents), "actions": len(actions),
                                               "tool_calls": len(tool_calls), "ms": elapsed})
    return {
        "run_id": run_id, "scenario": scenario, "version": __version__, "elapsed_ms": elapsed,
        "tool_server": server, "transport": transport,
        "findings": {k: v.to_dict() for k, v in findings.items()},
        "incidents": [i.to_dict() for i in incidents], "dismissed": dismissed,
        "actions": [a.to_dict() for a in actions], "review": issues,
        "stats": {"alerts": len(alerts), "tool_calls": len(tool_calls), "tool_budget": budget,
                  "denied_tool_calls": denied, "llm_calls": getattr(narrator, "calls", 0),
                  "llm_rejected": getattr(narrator, "rejected", 0)},
        "audit": audit,
    }
