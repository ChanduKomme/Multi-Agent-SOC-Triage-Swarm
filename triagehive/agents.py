"""The four agents of the swarm.

Author: Chandu Komme

* **TriageAgent** - the only agent with tools. Looks up context for one alert and
  turns it into a scored, explained finding (every factor cites evidence).
* **CorrelationAgent** - no tools. Links findings that share an entity within a
  time window into incidents and orders them along the kill chain.
* **ResponseAgent** - no tools. Drafts response actions from playbooks, each with
  a risk tier that decides how much human approval it needs.
* **ReviewerAgent** - no tools. Checks the other agents' work: coverage, evidence
  references, hallucinated targets, and dismissals of alerts that carried
  instruction-like text.

Each agent gets the minimum it needs, and hands off plain data, never free text
written by another agent that could carry instructions.
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from datetime import timedelta

from . import attack
from .guard import sanitise_alert, scan_alert
from .mcp import ToolClient, ToolError
from .memory import IncidentMemory
from .world import parse_time

__author__ = "Chandu Komme"

SEVERITIES = ["low", "medium", "high", "critical"]
EXTERNAL_FIELDS = ("src_ip", "dest_ip", "domain", "sha256")
MALICIOUS_AT, BENIGN_AT = 0.80, 0.25

# Telemetry wording that analysts treat as suspicious. Alert text is untrusted, so
# these signals can only *raise* suspicion: an attacker gains nothing by adding
# them, and no wording in an alert can ever lower a score.
HYGIENE = [
    ("unsigned_binary", 0.9, re.compile(r"\bunsigned\b", re.I)),
    ("staging_path", 0.9, re.compile(r"(?:^|[\s'\"])(?:/tmp|/var/tmp|/users/shared|/dev/shm)(?!\w)|\\(?:temp|appdata\\local\\temp|users\\public)\\", re.I)),
    ("encoded_command", 0.6, re.compile(r"\s-(?:enc|encodedcommand|e)(?:\s|$)|frombase64string", re.I)),
    ("lolbin_abuse", 0.7, re.compile(r"\b(?:mshta|rundll32|regsvr32|certutil|bitsadmin)(?:\.exe)?\b.{0,40}\b(?:http|minidump|comsvcs|remote|urlcache|\.hta)", re.I)),
    ("masquerading_name", 0.7, re.compile(r"\b(?:svchst|scvhost|lsas|explorer32|svch0st)\.exe\b", re.I)),
]


def is_internal(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.", "172.16."))


def sigmoid(z: float) -> float:
    return 1 / (1 + math.exp(-z))


@dataclass
class Factor:
    signal: str
    weight: float
    evidence: list[str]
    detail: str


@dataclass
class Finding:
    alert_id: str
    time: str
    rule: str
    entities: dict
    techniques: list[str]
    factors: list[Factor]
    probability: float
    verdict: str
    severity: str
    criticality: int
    precedents: list[dict] = field(default_factory=list)
    guard: list[dict] = field(default_factory=list)
    guard_score: float = 0.0
    input_problems: list[str] = field(default_factory=list)
    detail: str = ""
    reviewer_note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- triage
class TriageAgent:
    name = "triage"
    tools = {"asset_lookup", "identity_lookup", "intel_lookup", "geo_lookup", "rule_stats", "change_calendar"}

    def __init__(self, client: ToolClient, memory: IncidentMemory) -> None:
        self.client = client
        self.memory = memory

    def _lookup(self, tool: str, **args) -> dict | None:
        try:
            return self.client.call(self.name, tool, **args)
        except ToolError:
            return None

    def assess(self, raw: dict) -> Finding:
        alert, problems = sanitise_alert(raw)
        guard_hits, guard_score = scan_alert(alert)
        factors: list[Factor] = []

        def add(signal, weight, evidence, detail):
            factors.append(Factor(signal, round(weight, 2), [e for e in evidence if e], detail))

        rule = self._lookup("rule_stats", rule=alert.get("rule", "unknown")) or {"found": False}
        techniques = rule.get("attack", []) if rule.get("found") else []
        if rule.get("found"):
            base = {"high": 1.0, "medium": 0.0, "low": -1.0}[rule["severity"]]
            add("rule_severity", base, [rule["evidence_id"]], f"{rule['name']} is a {rule['severity']}-severity rule")
            add("rule_precision", (0.5 - rule["fp_rate"]) * 3, [rule["evidence_id"]],
                f"{rule['fp_rate']:.0%} false-positive rate over {rule['fires_90d']} firings in 90 days")
        else:
            add("unknown_rule", 0.5, [], "rule is not in the catalogue; treated cautiously")

        when = alert.get("time", "")
        host = alert.get("host")
        criticality = 2
        asset = self._lookup("asset_lookup", host=host) if host else None
        if asset and asset["found"]:
            criticality = asset["criticality"]

        user = alert.get("user")
        ident = self._lookup("identity_lookup", principal=user) if user and user != "SYSTEM" else None

        # --- threat intel and geography for external indicators
        verdicts = []
        for key in EXTERNAL_FIELDS:
            value = alert.get(key)
            if not value or (key.endswith("_ip") and is_internal(value)):
                continue
            intel = self._lookup("intel_lookup", indicator=value)
            if not intel:
                continue
            verdicts.append(intel["verdict"])
            if intel["verdict"] == "malicious":
                add("intel_malicious", 2.5 * intel["confidence"], [intel["evidence_id"]],
                    f"{value} is known malicious ({', '.join(intel['tags'])})")
            elif intel["verdict"] == "suspicious":
                add("intel_suspicious", 1.2 * intel["confidence"], [intel["evidence_id"]],
                    f"{value} is suspicious ({', '.join(intel['tags'])})")
            if key.endswith("_ip"):
                geo = self._lookup("geo_lookup", ip=value)
                if geo and geo.get("found"):
                    if geo["hosting"] and intel["verdict"] != "benign":
                        add("hosting_provider", 0.6, [geo["evidence_id"]], f"{value} belongs to a hosting provider ({geo['asn']})")
                    if ident and ident.get("found") and ident.get("home_countries"):
                        if geo["country"] in ident["home_countries"] and not geo["hosting"]:
                            add("expected_location", -1.2, [geo["evidence_id"], ident["evidence_id"]],
                                f"{value} is {geo['asn']} in {geo['country']}, a home country of {user}")
                        elif geo["country"] not in ident["home_countries"]:
                            add("unexpected_location", 0.8, [geo["evidence_id"], ident["evidence_id"]],
                                f"{user} has no history in {geo['country']}")
        if verdicts and all(v == "benign" for v in verdicts):
            add("intel_benign", -1.3, [], "every external indicator is known benign")

        # --- identity context
        if ident and ident.get("found"):
            if ident["privilege"] in ("high", "admin"):
                add("privileged_identity", 0.3, [ident["evidence_id"]], f"{user} is a {ident['privilege']}-privilege {ident['kind']} identity")
            src_host = alert.get("source_host")
            allowed = ident.get("allowed_hosts")
            if allowed and src_host and src_host not in allowed:
                add("account_misuse", 1.5, [ident["evidence_id"]], f"{user} is only expected on {', '.join(allowed)}, used from {src_host}")
            expected = ident.get("expected_sources")
            if expected and alert.get("src_ip") and not is_internal(alert["src_ip"]):
                add("account_misuse", 1.5, [ident["evidence_id"]], f"{user} should only act from {', '.join(expected)}, seen from {alert['src_ip']}")
            if ident["kind"] == "human" and when:
                hour = parse_time(when).hour
                start, end = ident["work_hours"]
                if not start <= hour < end:
                    add("off_hours", 0.4, [ident["evidence_id"]], f"{hour:02d}:00 UTC is outside {user}'s usual hours")

        # --- authoritative approval check (never trust approval claims in alert text)
        approved = None
        for target in filter(None, (host, user)):
            change = self._lookup("change_calendar", target=target, at=when) if when else None
            if change and change["approved"]:
                approved = change
                break
        if approved and "intel_malicious" not in {f.signal for f in factors}:
            add("approved_change", -2.0, [approved["evidence_id"]], f"covered by {approved['change_id']}: {approved['summary']}")

        # --- suspicious telemetry wording (raise-only)
        text = " ".join(str(alert.get(k, "")) for k in ("detail", "process"))
        for signal, weight, pattern in HYGIENE:
            if pattern.search(text):
                add(signal, weight, [], f"telemetry mentions {signal.replace('_', ' ')}")

        # --- attacker-controlled text that tries to steer triage is itself evidence
        if guard_hits:
            add("steering_text", 1.5 * guard_score / 0.6 if guard_score < 0.6 else 1.5, [],
                "alert text contains instructions aimed at the triage process: "
                + ", ".join(sorted({h.signal for h in guard_hits})))
            if any(h.signal == "claimed_approval" for h in guard_hits) and not approved:
                add("false_approval_claim", 1.0, [], "the alert text claims approval, but the change calendar has no matching change")

        # --- precedent from incident memory
        query = " ".join(str(alert.get(k, "")) for k in ("rule", "detail", "process", "user", "host"))
        precedents = self.memory.search(query, tuple(techniques))
        if precedents:
            top = precedents[0]
            shared = {t.split(".")[0] for t in techniques} & {t.split(".")[0] for t in top.techniques}
            if shared:
                add("precedent", 0.6 if top.verdict == "malicious" else -0.6, [top.doc_id],
                    f"similar to {top.doc_id} ({top.verdict}): {top.title}")

        score = sum(f.weight for f in factors)
        probability = round(sigmoid(score - 0.5), 3)
        verdict = "malicious" if probability >= MALICIOUS_AT else "benign" if probability <= BENIGN_AT else "needs_review"
        note = ""
        if guard_hits and verdict == "benign":
            verdict, note = "needs_review", "instruction-like text in the alert: never auto-dismissed"
        entities = {k: alert[k] for k in ("host", "source_host", "user", "src_ip", "dest_ip", "domain", "sha256") if alert.get(k)}
        return Finding(
            alert_id=alert.get("alert_id", "unknown"), time=when, rule=alert.get("rule", "unknown"), entities=entities,
            techniques=techniques, factors=factors, probability=probability, verdict=verdict,
            severity=alert_severity(probability, criticality, verdict), criticality=criticality,
            precedents=[{"id": p.doc_id, "title": p.title, "verdict": p.verdict, "score": p.score, "lesson": p.lesson}
                        for p in precedents],
            guard=[{"field": h.field, "signal": h.signal, "excerpt": h.excerpt} for h in guard_hits],
            guard_score=guard_score, input_problems=problems, detail=alert.get("detail", ""), reviewer_note=note,
        )


def alert_severity(probability: float, criticality: int, verdict: str) -> str:
    if verdict == "benign":
        return "low"
    level = 1 if probability < 0.6 else 2
    if probability >= 0.9 and criticality >= 4:
        level = 3
    if criticality >= 5 and verdict == "malicious":
        level = 3
    return SEVERITIES[level]


# ---------------------------------------------------------------------- correlation
@dataclass
class Incident:
    incident_id: str
    alert_ids: list[str]
    severity: str
    confidence: float
    status: str
    tactics: list[str]
    techniques: list[str]
    entities: dict
    links: list[dict]
    first_seen: str
    last_seen: str
    timeline: list[dict]
    title: str = ""
    summary: str = ""
    summary_source: str = "template"

    def to_dict(self) -> dict:
        return asdict(self)


PIVOTS = ("host", "source_host", "user", "src_ip", "dest_ip", "domain", "sha256")
NOT_PIVOTS = {"SYSTEM", "unknown"}


class CorrelationAgent:
    name = "correlation"

    def __init__(self, window_hours: float = 8.0) -> None:
        self.window = timedelta(hours=window_hours)

    def correlate(self, findings: list[Finding]) -> tuple[list[Incident], list[str]]:
        # A dismissed alert on a host or account that is confirmed compromised in
        # the same window is not routine any more: reopen it for a human.
        hot = [f for f in findings if f.verdict == "malicious"]
        for f in findings:
            if f.verdict != "benign":
                continue
            near = [m for m in hot if abs(parse_time(m.time) - parse_time(f.time)) <= self.window]
            shared = {p for m in near for p in pivots(m) & pivots(f) if p[0] in ("host", "user")}
            if shared:
                f.verdict, f.severity = "needs_review", "medium"
                f.reviewer_note = "reopened: shares " + ", ".join(sorted(v for _, v in shared)) + " with a confirmed malicious alert"
        live = [f for f in findings if f.verdict != "benign"]
        dismissed = [f.alert_id for f in findings if f.verdict == "benign"]
        parent = {f.alert_id: f.alert_id for f in live}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        links = []
        for i, a in enumerate(live):
            for b in live[i + 1:]:
                if abs(parse_time(a.time) - parse_time(b.time)) > self.window:
                    continue
                shared = pivots(a) & pivots(b)
                if shared:
                    links.append({"a": a.alert_id, "b": b.alert_id, "via": sorted(v for _, v in shared)})
                    parent[find(a.alert_id)] = find(b.alert_id)

        groups: dict[str, list[Finding]] = {}
        for f in live:
            groups.setdefault(find(f.alert_id), []).append(f)

        incidents = []
        for members in groups.values():
            members.sort(key=lambda f: f.time)
            ids = {f.alert_id for f in members}
            techniques = sorted({t for f in members for t in f.techniques})
            chain = attack.kill_chain(techniques)
            confidence = 1 - math.prod(1 - f.probability for f in members)
            level = max(SEVERITIES.index(f.severity) for f in members)
            if len(chain) >= 3 and confidence >= MALICIOUS_AT:
                level = max(level, 3)
            status = "confirmed" if any(f.verdict == "malicious" for f in members) else "needs_review"
            if status == "needs_review":
                level = min(level, 1)
            entities: dict[str, list[str]] = {}
            for f in members:
                for key, value in f.entities.items():
                    entities.setdefault(key, [])
                    if value not in entities[key]:
                        entities[key].append(value)
            incidents.append(Incident(
                incident_id="", alert_ids=[f.alert_id for f in members], severity=SEVERITIES[level],
                confidence=round(confidence, 3), status=status, tactics=chain, techniques=techniques,
                entities=entities, links=[l for l in links if l["a"] in ids],
                first_seen=members[0].time, last_seen=members[-1].time,
                timeline=[{"time": f.time, "alert_id": f.alert_id, "rule": f.rule,
                           "tactics": sorted({attack.tactic(t) for t in f.techniques}), "verdict": f.verdict}
                          for f in members],
            ))
        incidents.sort(key=lambda i: (-SEVERITIES.index(i.severity), -i.confidence, i.first_seen))
        for n, inc in enumerate(incidents, 1):
            inc.incident_id = f"INC-{n:03d}"
            inc.title = incident_title(inc)
            inc.summary = template_summary(inc)
        return incidents, dismissed


def pivots(f: Finding) -> set[tuple[str, str]]:
    out = set()
    for key in PIVOTS:
        value = f.entities.get(key)
        if not value or value in NOT_PIVOTS or (key.endswith("_ip") and is_internal(value)):
            continue
        kind = "host" if key in ("host", "source_host") else key
        out.add((kind, value))
    return out


def incident_title(inc: Incident) -> str:
    stages = " -> ".join(t.replace("-", " ") for t in inc.tactics) or "single alert"
    focus = (inc.entities.get("host") or inc.entities.get("user") or ["unknown"])[0]
    return f"{stages} around {focus}"


def template_summary(inc: Incident) -> str:
    parts = [f"{len(inc.alert_ids)} related alert(s) between {inc.first_seen} and {inc.last_seen}."]
    if inc.tactics:
        parts.append("Progression: " + ", ".join(inc.tactics) + ".")
    for key in ("host", "user", "src_ip", "dest_ip", "domain"):
        if inc.entities.get(key):
            parts.append(f"{key.replace('_', ' ')}: {', '.join(inc.entities[key])}.")
    return " ".join(parts)


# ------------------------------------------------------------------------- response
@dataclass
class Action:
    action_id: str
    incident_id: str
    tier: int
    kind: str
    target: str
    description: str
    rationale: str
    reversible: bool
    evidence: list[str]
    decision: str = "pending"
    approvers: list[str] = field(default_factory=list)
    decision_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class ResponseAgent:
    """Playbook-driven. Tier 0 = investigate, 1 = reversible containment, 2 = disruptive."""

    name = "response"

    def plan(self, incidents: list[Incident], findings: dict[str, Finding]) -> list[Action]:
        actions: list[Action] = []

        def act(inc, tier, kind, target, description, rationale, reversible, evidence):
            if any(a.incident_id == inc.incident_id and a.kind == kind and a.target == target for a in actions):
                return
            actions.append(Action(f"ACT-{len(actions) + 1:03d}", inc.incident_id, tier, kind, target, description,
                                  rationale, reversible, sorted(set(evidence))))

        for inc in incidents:
            members = [findings[a] for a in inc.alert_ids]
            ev = lambda f: [e for fac in f.factors for e in fac.evidence if e.startswith("EV-")]
            act(inc, 0, "open_case", inc.incident_id, f"Open a case for {inc.incident_id} and preserve evidence",
                "every incident gets a case and an evidence hold", True, [e for f in members for e in ev(f)][:6])
            if inc.status != "confirmed":
                continue
            tactics = set(inc.tactics)
            for f in members:
                host = f.entities.get("host")
                ftactics = {attack.tactic(t) for t in f.techniques}
                if host and f.criticality and host not in ("aws-prod", "aws-sandbox") and ftactics & {
                        "execution", "command-and-control", "credential-access"}:
                    tier = 2 if f.criticality >= 5 else 1
                    act(inc, tier, "isolate_host", host, f"Isolate {host} from the network with EDR containment",
                        f"{', '.join(sorted(ftactics))} observed on {host}", True, ev(f))
                if f.verdict == "malicious" and host and "lateral-movement" in ftactics:
                    act(inc, 2, "isolate_host", host, f"Isolate {host} (lateral-movement target, business-critical)",
                        "an attacker executed code here remotely", True, ev(f))
                for key in ("src_ip", "dest_ip"):
                    ip = f.entities.get(key)
                    if ip and not is_internal(ip) and any(fac.signal in ("intel_malicious", "intel_suspicious") for fac in f.factors):
                        act(inc, 1, "block_ip", ip, f"Block {ip} at the egress firewall and VPN", "known bad infrastructure", True, ev(f))
                domain = f.entities.get("domain")
                if domain and any(fac.signal == "intel_malicious" for fac in f.factors):
                    act(inc, 1, "block_domain", domain, f"Block {domain} at DNS and the web proxy", "known malicious domain", True, ev(f))
                if "credential-access" in ftactics:
                    # LSASS dumping exposes every account seen around the incident;
                    # MFA abuse only concerns the targeted user.
                    exposed = inc.entities.get("user", []) if "T1003.001" in f.techniques else [f.entities.get("user")]
                    for user in filter(None, exposed):
                        if user.startswith("svc_"):
                            act(inc, 2, "rotate_service_credential", user, f"Rotate credentials of service account {user}",
                                "credentials on the compromised host may be stolen; rotation can break dependent services", False, ev(f))
                        elif not user.startswith("role/") and user != "SYSTEM":
                            act(inc, 1, "reset_user", user, f"Revoke sessions and force a password reset for {user}",
                                "credential theft or MFA abuse observed", True, ev(f))
                if "privilege-escalation" in ftactics and f.entities.get("user"):
                    act(inc, 2, "disable_cloud_key", f.entities["user"], f"Disable access keys of {f.entities['user']}",
                        "the identity granted administrator rights from unexpected infrastructure", False, ev(f))
                    act(inc, 2, "revert_policy", "AdministratorAccess",
                        "Detach AdministratorAccess granted during the incident", "undo the privilege escalation", True, ev(f))
                if "collection" in ftactics or "exfiltration" in ftactics:
                    act(inc, 0, "scope_data_access", f.entities.get("host", "unknown"),
                        "Pull storage access logs and list the objects read", "size the data exposure", True, ev(f))
                    if f.entities.get("user", "").startswith("role/"):
                        act(inc, 1, "revoke_role_sessions", f.entities["user"], f"Revoke active sessions of {f.entities['user']}",
                            "stop ongoing downloads", True, ev(f))
        return actions


# ------------------------------------------------------------------------- reviewer
class ReviewerAgent:
    """A critic that checks the swarm's output before a human sees it."""

    name = "reviewer"

    def review(self, alert_ids: list[str], findings: dict[str, Finding], incidents: list[Incident],
               dismissed: list[str], actions: list[Action], evidence_ids: set[str], memory_ids: set[str]) -> list[dict]:
        issues = []

        def issue(kind, severity, message, ref=""):
            issues.append({"check": kind, "severity": severity, "message": message, "ref": ref})

        placed = [a for inc in incidents for a in inc.alert_ids] + dismissed
        for alert_id in alert_ids:
            count = placed.count(alert_id)
            if count != 1:
                issue("coverage", "error", f"{alert_id} appears {count} times in incidents and dismissals", alert_id)

        for f in findings.values():
            for fac in f.factors:
                for ev in fac.evidence:
                    if ev not in evidence_ids and ev not in memory_ids:
                        issue("evidence", "error", f"{f.alert_id} cites unknown evidence {ev}", f.alert_id)
            if f.guard and f.verdict == "benign":
                issue("steering_dismissal", "error", f"{f.alert_id} carried instruction-like text but was dismissed", f.alert_id)
            if f.verdict == "benign" and f.criticality >= 5 and f.probability > 0.15:
                issue("spot_check", "warning", f"{f.alert_id} on a critical asset was dismissed at p={f.probability}", f.alert_id)

        inc_ids = {i.incident_id: i for i in incidents}
        for a in actions:
            inc = inc_ids.get(a.incident_id)
            if inc is None:
                issue("action", "error", f"{a.action_id} references unknown incident {a.incident_id}", a.action_id)
                continue
            known = {v for vals in inc.entities.values() for v in vals} | {inc.incident_id, "AdministratorAccess"}
            if a.target not in known:
                issue("action", "error", f"{a.action_id} targets {a.target}, which is not in {inc.incident_id}", a.action_id)
            for ev in a.evidence:
                if ev not in evidence_ids:
                    issue("action", "error", f"{a.action_id} cites unknown evidence {ev}", a.action_id)
        return issues
