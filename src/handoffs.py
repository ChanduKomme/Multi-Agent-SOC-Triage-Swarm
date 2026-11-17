"""Validate the structured records passed between the three triage stages."""

from __future__ import annotations

import json
import re

from guardrails import clean_text, injection_signals

SEVERITIES = ("critical", "high", "medium", "low", "informational")
CONFIDENCES = ("high", "medium", "low")
FINDING_TEXT_FIELDS = ("asset_context", "identity_context", "intel_verdict", "rule_fidelity", "notes")
OWNERS = ("soc-l1", "soc-l2", "platform", "identity", "cloud")


class InvalidHandoff(ValueError):
    """A model response did not meet the handoff contract."""


def valid_id(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", value))


def _records(value: object, key: str) -> list[dict]:
    items = value.get(key) if isinstance(value, dict) else None
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise InvalidHandoff(f"Expected a list of objects in '{key}'.")
    return items


def _list_text(value: object, limit: int = 8) -> list[str]:
    if not isinstance(value, list):
        return []
    return [text for item in value[:limit] if (text := clean_text(item))]


def sanitise_finding(alert_id: str, raw: dict, hit_ids: list[str], source_flag: bool) -> dict:
    """Keep bounded findings and cite precedents from the actual retrieval hits."""
    references = raw.get("similar_past_incidents")
    precedents: dict[str, str] = {}
    if isinstance(references, list):
        for item in references:
            if isinstance(item, dict) and item.get("id") in hit_ids:
                precedents[item["id"]] = clean_text(item.get("why_relevant"))
    suspicion = raw.get("suspicion")
    return {
        "alert_id": alert_id,
        **{key: clean_text(raw.get(key)) for key in FINDING_TEXT_FIELDS},
        "suspicion": suspicion if suspicion in CONFIDENCES else "unknown",
        "similar_past_incidents": [
            {"id": doc_id, "why_relevant": why} for doc_id, why in precedents.items()
        ],
        "missing_context": _list_text(raw.get("missing_context")),
        "untrusted_content_flag": (
            source_flag
            or raw.get("untrusted_content_flag") is True
            or bool(injection_signals(json.dumps(raw, ensure_ascii=False)))
        ),
        "_rag_hits": hit_ids,
    }


def validate_incidents(raw: object, alert_ids: set[str]) -> dict:
    incidents = []
    seen_incidents: set[str] = set()
    seen_alerts: set[str] = set()
    for item in _records(raw, "incidents"):
        incident_id = item.get("incident_id")
        if not valid_id(incident_id) or incident_id in seen_incidents:
            raise InvalidHandoff("Correlation returned an invalid or duplicate incident ID.")
        members = item.get("alert_ids")
        if not isinstance(members, list) or not members:
            raise InvalidHandoff("Each incident must include at least one alert.")
        for member in members:
            if not valid_id(member) or member not in alert_ids or member in seen_alerts:
                raise InvalidHandoff("Correlation returned an invalid, unknown, or duplicate alert ID.")
            seen_alerts.add(member)
        severity, confidence = item.get("severity"), item.get("confidence")
        if severity not in SEVERITIES or confidence not in CONFIDENCES:
            raise InvalidHandoff("Correlation returned an invalid severity or confidence.")
        seen_incidents.add(incident_id)
        incidents.append({
            "incident_id": incident_id,
            "alert_ids": members,
            "title": clean_text(item.get("title"), limit=160) or "Candidate incident",
            "severity": severity,
            "confidence": confidence,
            "attack_chain": _list_text(item.get("attack_chain")),
            "rationale": clean_text(item.get("rationale")),
            "evidence_gaps": _list_text(item.get("evidence_gaps")),
        })
    if seen_alerts != alert_ids:
        raise InvalidHandoff("Correlation did not account for every input alert.")
    return {"incidents": incidents}


def validate_plans(raw: object, incident_ids: set[str]) -> dict:
    plans = []
    seen: set[str] = set()
    for item in _records(raw, "plans"):
        incident_id = item.get("incident_id")
        if not valid_id(incident_id) or incident_id not in incident_ids or incident_id in seen:
            raise InvalidHandoff("Response returned an invalid, unknown, or duplicate incident ID.")
        seen.add(incident_id)
        actions = []
        for step in _records(item, "actions"):
            action_type = clean_text(step.get("type"), limit=40) or "other"
            action = clean_text(step.get("action"), limit=400)
            if not action and action_type != "review_evidence":
                raise InvalidHandoff("Response returned a missing or unusable action description.")
            owner = step.get("owner")
            actions.append({
                "type": action_type,
                "action": action,
                "owner": owner if owner in OWNERS else "soc-l2",
                "justification": clean_text(step.get("justification")),
            })
        plans.append({
            "incident_id": incident_id,
            "actions": actions,
            "analyst_summary": clean_text(item.get("analyst_summary")),
            "escalate_to_human": item.get("escalate_to_human") is True,
        })
    if seen != incident_ids:
        raise InvalidHandoff("Response did not account for every validated incident.")
    return {"plans": plans}
