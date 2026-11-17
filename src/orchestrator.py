"""Orchestrator: sequences the three agents and owns every handoff.

Each handoff passes forward a bounded, structured record. The report preserves
every input alert, including when a stage cannot complete.

Flow:
    alerts.json
      -> EnrichmentAgent (MCP tools + RAG)   per alert  -> findings[]
      -> CorrelationAgent                               -> incidents
      -> ResponseAgent (+ ApprovalGate)                 -> plans
      -> render_report()                                -> out/soc_triage_report.md
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from agents import CorrelationAgent, EnrichmentAgent, ResponseAgent
from guardrails import ApprovalGate, Budget
from handoffs import InvalidHandoff, SEVERITIES, valid_id, validate_incidents, validate_plans
from mcp_client import mcp_tool_layer
from rag_store import IncidentRagStore

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OUT = ROOT / "out"

def load_alerts(limit: int | None) -> list[dict]:
    if limit is not None and limit < 1:
        raise ValueError("The alert limit must be positive.")
    alerts = json.loads((DATA / "alerts.json").read_text(encoding="utf-8"))
    if not isinstance(alerts, list) or not alerts:
        raise ValueError("alerts.json must contain a non-empty list of alerts.")
    batch = alerts[:limit]
    seen: set[str] = set()
    for alert in batch:
        alert_id = alert.get("alert_id") if isinstance(alert, dict) else None
        if not valid_id(alert_id) or alert_id in seen:
            raise ValueError("Each alert must have a valid, unique alert_id.")
        seen.add(alert_id)
    return batch


async def run(auto_approve: bool = False, limit: int | None = None) -> dict:
    alerts = load_alerts(limit)
    alert_ids = [alert["alert_id"] for alert in alerts]
    rag = IncidentRagStore(DATA / "past_incidents")
    budget = Budget(max_llm_calls=len(alerts) * 3 + 6)
    gate = ApprovalGate(auto_approve=auto_approve)
    warnings = []

    print(f"[orchestrator] {len(alerts)} alerts | model budget {budget.max_llm_calls} LLM calls")

    findings: list[dict] = []
    async with mcp_tool_layer(limit=limit) as tools:
        print(f"[orchestrator] MCP tool layer up: {[t['name'] for t in tools.tools]}")
        enricher = EnrichmentAgent(tools, rag, budget)
        for index, alert in enumerate(alerts):
            # Leave one call for each later alert and one each for correlation and response.
            reserved = len(alerts) - index - 1 + 2
            available = budget.max_llm_calls - budget.llm_calls - reserved
            finding = await enricher.enrich(alert, min(budget.max_agent_turns, available))
            if finding["enrichment_failed"]:
                warnings.append(f"Enrichment was incomplete for {finding['alert_id']}.")
            flag = " [UNTRUSTED-TEXT]" if finding.get("untrusted_content_flag") else ""
            print(f"  enriched {finding['alert_id']}: suspicion={finding.get('suspicion')}{flag}")
            findings.append(finding)

    print(f"[orchestrator] handoff -> correlation ({tools.call_count} MCP calls used)")
    incidents = {"incidents": []}
    plans = {"plans": []}
    unassigned = alert_ids
    try:
        incidents = validate_incidents(CorrelationAgent(budget).correlate(alerts, findings), set(alert_ids))
        unassigned = []
    except InvalidHandoff as exc:
        warnings.append(f"Correlation needs manual review. {exc}")
    except Exception as exc:
        warnings.append(f"Correlation did not complete ({type(exc).__name__}).")

    if not unassigned:
        print(f"[orchestrator] {len(incidents['incidents'])} candidate incidents")
        try:
            known_incidents = {incident["incident_id"] for incident in incidents["incidents"]}
            plans = validate_plans(ResponseAgent(budget).plan(incidents, findings), known_incidents)
        except InvalidHandoff as exc:
            warnings.append(f"Response needs manual review. {exc}")
        except Exception as exc:
            warnings.append(f"Response planning did not complete ({type(exc).__name__}).")
        for plan in plans["plans"]:
            for action in plan["actions"]:
                action.update(gate.review(plan["incident_id"], action["action"], action["type"]))

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "alert_count": len(alerts),
        "findings": findings,
        "incidents": incidents,
        "plans": plans,
        "approvals": gate.decisions,
        "status": "needs_review" if warnings else "complete",
        "warnings": warnings,
        "unassigned_alerts": unassigned,
        "budget": budget.summary(),
        "mcp_tool_calls": tools.call_count,
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "triage_run.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (OUT / "soc_triage_report.md").write_text(render_report(result), encoding="utf-8")
    print(f"[orchestrator] done. budget: {result['budget']}")
    print(f"[orchestrator] report: {OUT / 'soc_triage_report.md'}")
    return result


def markdown_text(value: str) -> str:
    """Display model-generated text without turning it into Markdown markup."""
    text = escape(value, quote=False)
    for character in ("\\", "*", "_", "[", "]", "|", "~", "`"):
        text = text.replace(character, "\\" + character)
    return text


def evidence_lines(finding: dict) -> list[str]:
    text = markdown_text
    lines = [
        f"- `{finding['alert_id']}` — suspicion **{finding['suspicion']}**. "
        f"Intel: {text(finding.get('intel_verdict') or 'n/a')}. "
        f"Identity: {text(finding.get('identity_context') or 'n/a')}. "
        f"Rule fidelity: {text(finding.get('rule_fidelity') or 'n/a')}."
    ]
    for past in finding["similar_past_incidents"]:
        lines.append(f"  - Precedent **{text(past['id'])}**. {text(past['why_relevant'])}")
    for gap in finding["missing_context"]:
        lines.append(f"  - Evidence gap. {text(gap)}")
    return lines


def render_report(r: dict) -> str:
    by_id = {f["alert_id"]: f for f in r["findings"]}
    sev_order = {severity: order for order, severity in enumerate(SEVERITIES)}
    incidents = sorted(
        r["incidents"].get("incidents", []), key=lambda i: sev_order.get(i.get("severity", "low"), 9)
    )
    plans = {p["incident_id"]: p for p in r["plans"].get("plans", [])}
    usage = r["budget"]

    lines = [
        "# SOC Triage Report (multi-agent swarm)",
        "",
        f"Generated: {r['generated_at']}  |  Alerts: {r['alert_count']}  |  "
        f"Incidents: {len(incidents)}  |  MCP tool calls: {r['mcp_tool_calls']}",
        "",
        f"**Run status:** {r['status'].replace('_', ' ').capitalize()}",
        "",
        "> Machine-generated triage. Severity and confidence are model judgments.",
        "> The approval gate records analyst decisions. All actions are recommendations.",
        "",
        "## Incident summary",
        "",
        "| Incident | Severity | Confidence | Alerts | Title |",
        "|---|---|---|---|---|",
    ]
    for i in incidents:
        lines.append(
            f"| {i['incident_id']} | **{i.get('severity')}** | {i.get('confidence')} | "
            f"{', '.join(i['alert_ids'])} | {markdown_text(i['title'])} |"
        )

    if r["warnings"]:
        lines += ["", "## Run warnings", ""]
        lines.extend(f"- {markdown_text(warning)}" for warning in r["warnings"])

    if r["unassigned_alerts"]:
        lines += ["", "## Alerts awaiting manual grouping", ""]
        for alert_id in r["unassigned_alerts"]:
            lines.extend(evidence_lines(by_id[alert_id]))

    flagged = [f["alert_id"] for f in r["findings"] if f.get("untrusted_content_flag")]
    if flagged:
        lines += [
            "",
            "## Guardrail flags",
            "",
            f"Instruction-like text was flagged in the context for **{', '.join(flagged)}**. "
            "Review the source evidence before making a disposition.",
        ]

    for i in incidents:
        lines += ["", f"## {i['incident_id']} — {markdown_text(i['title'])}", ""]
        lines.append(f"- **Severity:** {i.get('severity')} (confidence {i.get('confidence')})")
        lines.append(f"- **Alerts:** {', '.join(i.get('alert_ids', []))}")
        if i.get("attack_chain"):
            lines.append(f"- **Attack chain:** {markdown_text(' → '.join(i['attack_chain']))}")
        if i["rationale"]:
            lines.append(f"- **Rationale:** {markdown_text(i['rationale'])}")
        if i.get("evidence_gaps"):
            lines += ["- **Evidence gaps:**"]
            lines.extend(f"  - {markdown_text(gap)}" for gap in i["evidence_gaps"])

        lines += ["", "### Enrichment evidence", ""]
        for alert_id in i["alert_ids"]:
            lines.extend(evidence_lines(by_id[alert_id]))

        plan = plans.get(i["incident_id"])
        if plan:
            lines += ["", "### Recommended response", ""]
            if plan["analyst_summary"]:
                lines.append(markdown_text(plan["analyst_summary"]))
            if plan["actions"]:
                lines += [
                    "", "| # | Action | Owner | Human approval | Decision |", "|---|---|---|---|---|"
                ]
                for n, a in enumerate(plan["actions"], 1):
                    lines.append(
                        f"| {n} | {markdown_text(a['action'])} | {a['owner']} | "
                        f"{'Required' if a['requires_approval'] else 'Routine'} | {a['approval']} |"
                    )
            if plan.get("escalate_to_human"):
                lines.append("\n**Analyst review recommended.**")

    lines += [
        "", "## Usage", "",
        f"Model calls: {usage['llm_calls']} / {usage['llm_call_limit']}. "
        f"Input tokens: {usage['input_tokens']}. Output tokens: {usage['output_tokens']}.",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    from run_triage import main

    main()
