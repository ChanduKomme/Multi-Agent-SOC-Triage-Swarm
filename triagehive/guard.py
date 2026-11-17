"""Guardrails between untrusted data and the agents.

Author: Chandu Komme

Alert fields such as ``detail`` and ``note`` are written, directly or
indirectly, by whoever caused the alert, so an attacker can put text there.
This module:

* scans every free-text field for instruction-like content aimed at an AI or
  at the triage process ("mark as false positive", "do not escalate", ...)
* treats such text as a **signal of attack** in itself, never as guidance
* wraps untrusted text in labelled fences ("spotlighting") before it reaches
  any language model, and strips anything that could close the fence early
* enforces structural limits (field length, identifier formats)
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

__author__ = "Chandu Komme"

FREE_TEXT_FIELDS = ("detail", "note", "process")
ID_FIELDS = ("alert_id", "rule", "host", "user", "src_ip", "dest_ip", "domain", "sha256", "source_host")
_ID_OK = re.compile(r"^[\w.:/@\-$]{1,128}$")
MAX_TEXT = 600

_PATTERNS = [
    ("addresses_ai", 0.35, r"\b(?:ai|assistant|chatbot|llm|model|copilot|triage bot)\b\s*[:,]"),
    ("override", 0.5, r"\b(?:ignore|disregard|forget|override)\b.{0,30}\b(?:previous|prior|above|earlier|all)?\s*(?:instructions?|rules|policy|guidance)"),
    ("verdict_steering", 0.5, r"\b(?:mark|classify|treat|label|close|resolve)\b.{0,30}\b(?:false positive|benign|resolved|closed|safe|expected)"),
    ("suppress_escalation", 0.45, r"\b(?:do not|don't|never|no need to)\s+(?:escalate|alert|notify|page|report|investigate|open a ticket)"),
    ("claimed_approval", 0.3, r"\b(?:approved|authori[sz]ed|sanctioned)\s+(?:maintenance|change|activity|transfer|by (?:it|security|the soc))"),
    ("role_marker", 0.4, r"(?:^|\s)(?:system|assistant|developer)\s*:|\[(?:system|inst)\]|<\|im_start\|>"),
    ("tool_steering", 0.4, r"\b(?:call|invoke|run|execute)\s+(?:the\s+)?(?:tool|function|command)\b"),
]
_RULES = [(name, weight, re.compile(p, re.I)) for name, weight, p in _PATTERNS]
_INVISIBLE = dict.fromkeys(map(ord, "​‌‍⁠﻿‮‭"))


@dataclass(frozen=True)
class GuardFinding:
    field: str
    signal: str
    excerpt: str


def normalise(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).translate(_INVISIBLE).split())


def scan_alert(alert: dict) -> tuple[list[GuardFinding], float]:
    """Return instruction-like findings in the alert's free text, plus a 0..1 score."""
    findings: list[GuardFinding] = []
    remaining = 1.0
    for field in FREE_TEXT_FIELDS:
        value = alert.get(field)
        if not isinstance(value, str):
            continue
        text = normalise(value)
        for name, weight, pattern in _RULES:
            match = pattern.search(text)
            if match:
                findings.append(GuardFinding(field, name, text[max(0, match.start() - 20):match.end() + 20][:120]))
                remaining *= 1 - weight
    return findings, round(1 - remaining, 3)


def sanitise_alert(raw: dict) -> tuple[dict, list[str]]:
    """Keep only known fields with sane values; report what was dropped."""
    clean, problems = {}, []
    for key in ID_FIELDS + ("time",):
        value = raw.get(key)
        if value is None:
            continue
        if key == "time" or _ID_OK.match(str(value)):
            clean[key] = str(value)
        else:
            problems.append(f"{key} has an invalid value and was dropped")
    for key in FREE_TEXT_FIELDS:
        value = raw.get(key)
        if isinstance(value, str):
            text = normalise(value)
            if len(text) > MAX_TEXT:
                problems.append(f"{key} truncated from {len(text)} characters")
                text = text[:MAX_TEXT]
            clean[key] = text
    unknown = set(raw) - set(ID_FIELDS) - set(FREE_TEXT_FIELDS) - {"time", "truth"}
    problems += [f"unknown field {k!r} ignored" for k in sorted(unknown)]
    return clean, problems


def spotlight(label: str, text: str) -> str:
    """Fence untrusted text for an LLM prompt so it is read as data, not instructions."""
    safe = re.sub(r"</?untrusted[^>]*>", "[tag removed]", text, flags=re.I)
    return f'<untrusted source="{label}">\n{safe}\n</untrusted>'
