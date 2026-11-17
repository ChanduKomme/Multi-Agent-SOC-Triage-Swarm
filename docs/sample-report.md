# SOC Triage Report (multi-agent swarm)

> Sample run with scripted model responses and actual local MCP lookups. Token counts are scripted and approval is simulated.

Generated: 2026-11-17T01:07:29+00:00  |  Alerts: 8  |  Incidents: 3  |  MCP tool calls: 24

**Run status:** Complete

> Machine-generated triage. Severity and confidence are model judgments.
> The approval gate records analyst decisions. All actions are recommendations.

## Incident summary

| Incident | Severity | Confidence | Alerts | Title |
|---|---|---|---|---|
| CAND-001 | **critical** | medium | ALT-9001, ALT-9002, ALT-9003, ALT-9007 | Suspected compromise of a payments service account |
| CAND-002 | **high** | medium | ALT-9004, ALT-9005, ALT-9008 | Endpoint execution after a phishing click |
| CAND-003 | **low** | low | ALT-9006 | Bulk export with instruction-like text |

## Guardrail flags

Instruction-like text was flagged in the context for **ALT-9004, ALT-9006**. Review the source evidence before making a disposition.

## CAND-001 — Suspected compromise of a payments service account

- **Severity:** critical (confidence medium)
- **Alerts:** ALT-9001, ALT-9002, ALT-9003, ALT-9007
- **Attack chain:** credential access → anomalous sign-in → outbound transfer → cloud privilege change
- **Rationale:** A shared service principal and external indicator connect the access and cloud events. The payments host also generated the credential-access and transfer alerts.
- **Evidence gaps:**
  - Confirm the session IDs and establish whether the outbound transfer contained sensitive data.

### Enrichment evidence

- `ALT-9001` — suspicion **high**. Intel: 10.42.7.31 rated internal in mock intel. Identity: Privileged service account (svc\_payments). Rule fidelity: 4 hits in 90 days, 75% historical true-positive rate.
  - Precedent **INC-2024-0117-credential-theft**. Same service account and a comparable EDR signal
- `ALT-9002` — suspicion **high**. Intel: 203.0.113.44 rated malicious in mock intel. Identity: Privileged service account (svc\_payments). Rule fidelity: 122 hits in 90 days, 6% historical true-positive rate.
  - Precedent **INC-2024-0117-credential-theft**. Identity anomaly follows credential access
- `ALT-9003` — suspicion **high**. Intel: 203.0.113.44 rated malicious in mock intel. Identity: Privileged service account (svc\_payments). Rule fidelity: 31 hits in 90 days, 19% historical true-positive rate.
  - Precedent **INC-2024-0117-credential-theft**. Large outbound transfer on the payments host
- `ALT-9007` — suspicion **high**. Intel: 203.0.113.44 rated malicious in mock intel. Identity: Privileged service account (svc\_payments). Rule fidelity: 6 hits in 90 days, 50% historical true-positive rate.
  - Precedent **INC-2025-0151-cloud-privesc**. Administrative grant followed an anomalous sign-in

### Recommended response

Confirm access scope with the payments owner and preserve the relevant records.

| # | Action | Owner | Human approval | Decision |
|---|---|---|---|---|
| 1 | Isolate fin-app-07 after the payments owner confirms the containment window. | platform | Required | demo approval (simulated) |
| 2 | Review existing evidence for CAND-001. | soc-l2 | Routine | routine review |

**Analyst review recommended.**

## CAND-002 — Endpoint execution after a phishing click

- **Severity:** high (confidence medium)
- **Alerts:** ALT-9004, ALT-9005, ALT-9008
- **Attack chain:** phishing → execution → possible persistence
- **Rationale:** The host and user match across all three alerts. The rule history and task signer matter when evaluating persistence.
- **Evidence gaps:**
  - Verify the scheduled task signer and the endpoint process tree.

### Enrichment evidence

- `ALT-9004` — suspicion **medium**. Intel: 198.51.100.9 rated malicious in mock intel. Identity: Standard human (anita.rao). Rule fidelity: 58 hits in 90 days, 34% historical true-positive rate.
  - Precedent **INC-2025-0042-phishing-to-execution**. Phishing preceded execution on the same endpoint
- `ALT-9005` — suspicion **high**. Intel: 10.13.4.88 rated unknown in mock intel. Identity: Standard human (anita.rao). Rule fidelity: 9 hits in 90 days, 66% historical true-positive rate.
  - Precedent **INC-2025-0042-phishing-to-execution**. Office spawned PowerShell after a phishing event
- `ALT-9008` — suspicion **medium**. Intel: 10.13.4.88 rated unknown in mock intel. Identity: Standard human (anita.rao). Rule fidelity: 340 hits in 90 days, 3% historical true-positive rate.
  - Precedent **INC-2025-0244-noisy-scheduled-task**. Rule is noisy and needs a signer and file-path check
  - Precedent **INC-2025-0042-phishing-to-execution**. A scheduled task can also follow phishing and Office execution

### Recommended response

Use the process tree and task signer to confirm whether the alerts form one incident.

| # | Action | Owner | Human approval | Decision |
|---|---|---|---|---|
| 1 | Review existing evidence for CAND-002. | soc-l2 | Routine | routine review |

## CAND-003 — Bulk export with instruction-like text

- **Severity:** low (confidence low)
- **Alerts:** ALT-9006
- **Rationale:** The export resembles a prior benign case. The input flag warrants a source review before anyone chooses a disposition.
- **Evidence gaps:**
  - Confirm the export destination and who supplied the alert note.

### Enrichment evidence

- `ALT-9006` — suspicion **low**. Intel: 10.13.9.14 rated unknown in mock intel. Identity: Standard human (ravi.k). Rule fidelity: 210 hits in 90 days, 2% historical true-positive rate.
  - Precedent **INC-2025-0088-benign-bulk-export**. Export volume and role match an earlier benign case
  - Evidence gap. Export destination and alert note provenance

### Recommended response

Compare the export with approved reporting activity and verify the alert note's provenance.

| # | Action | Owner | Human approval | Decision |
|---|---|---|---|---|
| 1 | Review existing evidence for CAND-003. | soc-l1 | Routine | routine review |

**Analyst review recommended.**

## Usage

Model calls: 18 / 30. Input tokens: 1800. Output tokens: 720.
