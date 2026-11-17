"""Report writers: Markdown case report, JSON record and an offline HTML dashboard.

Author: Chandu Komme

Alert text is attacker-controlled, so every value is escaped for its output
format: Markdown control characters in the report, HTML entities in the
dashboard (which also ships a strict Content-Security-Policy and no scripts).
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

from . import attack

__author__ = "Chandu Komme"

BADGE = {"critical": "#ff4d6d", "high": "#ff9f1c", "medium": "#ffd166", "low": "#4cc9f0"}


def md(value) -> str:
    text = " ".join(str(value).split())
    return re.sub(r"([\\`*_{}\[\]<>()#+!|])", r"\\\1", text)


def write_all(result: dict, out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {"markdown": out / "triage_report.md", "json": out / "triage_run.json",
             "html": out / "dashboard.html", "audit": out / "audit.jsonl"}
    paths["markdown"].write_text(markdown(result), encoding="utf-8")
    record = {k: v for k, v in result.items() if k != "audit"}
    paths["json"].write_text(json.dumps(record, indent=2), encoding="utf-8")
    paths["html"].write_text(dashboard(result), encoding="utf-8")
    result["audit"].write(paths["audit"])
    return paths


def markdown(r: dict) -> str:
    f, incs = r["findings"], r["incidents"]
    L = [f"# TriageHive report: {md(r['scenario'])}", "",
         f"Run `{r['run_id']}` · {r['stats']['alerts']} alerts · {len(incs)} incidents · "
         f"{len(r['dismissed'])} dismissed · {r['stats']['tool_calls']} tool calls over MCP ({r['transport']}) · "
         f"{r['elapsed_ms']} ms", ""]
    errors = [i for i in r["review"] if i["severity"] == "error"]
    L += [f"**Reviewer:** {'PASS' if not errors else 'FAIL'} "
          f"({len(errors)} errors, {len(r['review']) - len(errors)} warnings)", ""]
    L += ["## Incidents", "", "| Incident | Severity | Status | Confidence | Alerts | Kill chain |", "|---|---|---|---|---|---|"]
    for i in incs:
        L.append(f"| {i['incident_id']} | **{i['severity']}** | {i['status']} | {i['confidence']:.2f} | "
                 f"{len(i['alert_ids'])} | {' → '.join(i['tactics']) or '-'} |")
    for i in incs:
        L += ["", f"### {i['incident_id']}: {md(i['title'])}", "", md(i["summary"]) +
              (" *(summary written by the language model and checked against the facts)*" if i["summary_source"] == "llm" else ""), "",
              "| Time (UTC) | Alert | Rule | Verdict | p | Techniques |", "|---|---|---|---|---|---|"]
        for alert_id in i["alert_ids"]:
            a = f[alert_id]
            L.append(f"| {a['time'][11:19]} | {alert_id} | {md(a['rule'])} | {a['verdict']} | {a['probability']:.2f} | "
                     f"{', '.join(a['techniques'])} |")
        L += ["", "**Why:**"]
        for alert_id in i["alert_ids"]:
            a = f[alert_id]
            top = sorted(a["factors"], key=lambda x: -abs(x["weight"]))[:3]
            reasons = "; ".join(f"{md(x['detail'])} ({x['weight']:+.1f}, {', '.join(x['evidence']) or 'guard'})" for x in top)
            L.append(f"- {alert_id}: {reasons}")
            if a["guard"]:
                L.append(f"  - ⚠️ steering text in `{a['guard'][0]['field']}`: "
                         f"{', '.join(sorted({g['signal'] for g in a['guard']}))}. Treated as evidence of attack, not as guidance.")
        if i["links"]:
            L += ["", "**Correlated via:** " + "; ".join(f"{l['a']}↔{l['b']} ({', '.join(md(v) for v in l['via'])})"
                                                         for l in i["links"][:8])]
        acts = [a for a in r["actions"] if a["incident_id"] == i["incident_id"]]
        L += ["", "| Action | Tier | Proposed step | Decision | Approvers |", "|---|---|---|---|---|"]
        for a in acts:
            L.append(f"| {a['action_id']} | {a['tier']} | {md(a['description'])} | {a['decision']} | {', '.join(a['approvers']) or '-'} |")
    L += ["", "## Dismissed as expected activity", "", "| Alert | Rule | p | Main reason |", "|---|---|---|---|"]
    for alert_id in r["dismissed"]:
        a = f[alert_id]
        top = min(a["factors"], key=lambda x: x["weight"])
        L.append(f"| {alert_id} | {md(a['rule'])} | {a['probability']:.2f} | {md(top['detail'])} |")
    if r["review"]:
        L += ["", "## Reviewer notes", ""] + [f"- **{i['severity']}** [{i['check']}] {md(i['message'])}" for i in r["review"]]
    L += ["", "## Approval policy", "",
          "Tier 0 (investigate) is automatic, tier 1 (reversible containment) needs one analyst, tier 2 (disruptive or "
          "business-critical) needs two different analysts. Nothing is executed by TriageHive.", "",
          f"Audit trail: `audit.jsonl` (hash-chained, verify with `python -m triagehive verify-audit`)."]
    return "\n".join(L) + "\n"


def dashboard(r: dict) -> str:
    e = html.escape
    f = r["findings"]
    cards = []
    for i in r["incidents"]:
        rows = "".join(
            f"<tr><td>{e(f[a]['time'][11:19])}</td><td>{e(a)}</td><td>{e(f[a]['rule'])}</td>"
            f"<td>{e(', '.join(attack.kill_chain(f[a]['techniques'])))}</td>"
            f"<td><div class='bar'><span style='width:{f[a]['probability'] * 100:.0f}%'></span></div></td>"
            f"<td>{'⚠️' if f[a]['guard'] else ''}</td></tr>" for a in i["alert_ids"])
        acts = "".join(f"<li class='t{a['tier']}'><b>{e(a['action_id'])}</b> tier {a['tier']} · {e(a['description'])} "
                       f"<em class='{e(a['decision'])}'>{e(a['decision'].replace('_', ' '))}</em></li>"
                       for a in r["actions"] if a["incident_id"] == i["incident_id"])
        chain = "".join(f"<span class='stage{' on' if t in i['tactics'] else ''}'>{e(t.replace('-', ' '))}</span>"
                        for t in attack.TACTIC_ORDER)
        cards.append(f"""<section class="card"><header><span class="sev" style="background:{BADGE[i['severity']]}">{e(i['severity'])}</span>
<h2>{e(i['incident_id'])} · {e(i['title'])}</h2><span class="conf">confidence {i['confidence']:.2f}</span></header>
<p>{e(i['summary'])}</p><div class="chain">{chain}</div>
<table><tr><th>UTC</th><th>Alert</th><th>Rule</th><th>Tactic</th><th>Malicious probability</th><th></th></tr>{rows}</table>
<h3>Proposed response</h3><ul class="acts">{acts}</ul></section>""")
    dismissed = "".join(f"<li>{e(a)} · {e(f[a]['rule'])} · p={f[a]['probability']:.2f}</li>" for a in r["dismissed"])
    errors = sum(1 for i in r["review"] if i["severity"] == "error")
    stats = [("alerts", r["stats"]["alerts"]), ("incidents", len(r["incidents"])), ("dismissed", len(r["dismissed"])),
             ("tool calls", r["stats"]["tool_calls"]), ("pending approvals", sum(a["decision"] == "pending" for a in r["actions"])),
             ("reviewer", "PASS" if not errors else f"{errors} errors")]
    tiles = "".join(f"<div class='tile'><b>{e(str(v))}</b><span>{e(k)}</span></div>" for k, v in stats)
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>TriageHive · {e(r['scenario'])}</title>
<style>
:root{{--bg:#0b1020;--panel:#121a33;--line:#24305a;--text:#e6ecff;--dim:#8a96c2;--accent:#f7b32b}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,Segoe UI,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:28px}}h1{{margin:0;font-size:26px}}h1 span{{color:var(--accent)}}
.sub{{color:var(--dim);margin:4px 0 22px}}.tiles{{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:22px}}
.tile{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px}}.tile b{{display:block;font-size:22px}}
.tile span{{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.05em}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;margin-bottom:18px}}
.card header{{display:flex;align-items:center;gap:12px}}.card h2{{font-size:17px;margin:0;flex:1}}
.sev{{color:#111;font-weight:700;padding:3px 10px;border-radius:999px;text-transform:uppercase;font-size:11px}}
.conf{{color:var(--dim)}}table{{width:100%;border-collapse:collapse;margin-top:10px}}td,th{{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left}}
th{{color:var(--dim);font-weight:500;font-size:12px}}.bar{{background:#1d274b;border-radius:4px;height:8px;width:140px}}
.bar span{{display:block;height:8px;border-radius:4px;background:linear-gradient(90deg,#ffd166,#ff4d6d)}}
.chain{{display:flex;flex-wrap:wrap;gap:4px;margin:8px 0}}.stage{{font-size:11px;padding:2px 7px;border-radius:5px;background:#1a2242;color:#56608a}}
.stage.on{{background:#3b2a07;color:var(--accent);border:1px solid #6b4c0c}}h3{{font-size:13px;color:var(--dim);margin:14px 0 6px}}
.acts{{list-style:none;padding:0;margin:0}}.acts li{{padding:6px 0;border-bottom:1px dashed var(--line)}}
.acts em{{float:right;font-style:normal;font-size:12px;padding:1px 8px;border-radius:5px;background:#1d274b}}
.acts em.pending{{color:#ffd166}}.acts em.approved,.acts em.auto_approved{{color:#7ae582}}.acts em.denied{{color:#ff4d6d}}
.dis{{color:var(--dim)}}footer{{color:var(--dim);font-size:12px;margin-top:20px}}
</style></head><body><main>
<h1>Triage<span>Hive</span> · {e(r['scenario'])}</h1>
<p class="sub">Run {e(r['run_id'])} · TriageHive {e(r['version'])} · tools served over MCP ({e(r['transport'])}) · {r['elapsed_ms']} ms</p>
<div class="tiles">{tiles}</div>{''.join(cards)}
<section class="card"><h2>Dismissed as expected activity</h2><ul class="dis">{dismissed or '<li>none</li>'}</ul></section>
<footer>Generated offline by TriageHive · by Chandu Komme · all data in this demo is fictional</footer>
</main></body></html>"""
