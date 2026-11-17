# TriageHive report: night-shift

Run `2b4d4abc4e31` · 13 alerts · 2 incidents · 5 dismissed · 73 tool calls over MCP (stdio) · 55.2 ms

**Reviewer:** PASS (0 errors, 0 warnings)

## Incidents

| Incident | Severity | Status | Confidence | Alerts | Kill chain |
|---|---|---|---|---|---|
| INC-001 | **critical** | confirmed | 1.00 | 3 | privilege-escalation → credential-access → collection |
| INC-002 | **critical** | confirmed | 1.00 | 5 | initial-access → execution → credential-access → lateral-movement → command-and-control |

### INC-001: privilege escalation -\> credential access -\> collection around aws-prod

3 related alert\(s\) between 2026-11-17T02:31:55Z and 2026-11-17T03:24:17Z. Progression: privilege-escalation, credential-access, collection. host: aws-prod. user: k.novak, ci-deployer, role/DataEngineer. src ip: 198.51.100.23. dest ip: 198.51.100.77.

| Time (UTC) | Alert | Rule | Verdict | p | Techniques |
|---|---|---|---|---|---|
| 02:31:55 | ALT-3102 | IDP-MFA-FATIGUE | malicious | 0.99 | T1621 |
| 03:09:41 | ALT-3104 | CLOUD-IAM-ADMIN-GRANT | malicious | 0.99 | T1098.003 |
| 03:24:17 | ALT-3105 | CLOUD-MASS-DOWNLOAD | malicious | 1.00 | T1530 |

**Why:**
- ALT-3102: 10% false-positive rate over 9 firings in 90 days (+1.2, EV-008); Burst of MFA push requests is a high-severity rule (+1.0, EV-008); 198.51.100.23 is suspicious \(vps, anonymiser, credential-stuffing\) (+0.8, EV-010)
- ALT-3104: ci-deployer should only act from build-07, seen from 198.51.100.23 (+1.5, EV-019); Administrator policy attached to an identity is a high-severity rule (+1.0, EV-017); 20% false-positive rate over 14 firings in 90 days (+0.9, EV-017)
- ALT-3105: 198.51.100.77 is known malicious \(exfiltration, bulletproof-hosting\) (+2.1, EV-029); alert text contains instructions aimed at the triage process: addresses\_ai, claimed\_approval, role\_marker, suppress\_escalation, verdict\_steering (+1.5, guard); Mass object download from cloud storage is a high-severity rule (+1.0, EV-024)
  - ⚠️ steering text in `note`: addresses_ai, claimed_approval, role_marker, suppress_escalation, verdict_steering. Treated as evidence of attack, not as guidance.

**Correlated via:** ALT-3102↔ALT-3104 (198.51.100.23); ALT-3102↔ALT-3105 (198.51.100.23); ALT-3104↔ALT-3105 (198.51.100.23, aws-prod)

| Action | Tier | Proposed step | Decision | Approvers |
|---|---|---|---|---|
| ACT-001 | 0 | Open a case for INC-001 and preserve evidence | auto_approved | policy:tier0 |
| ACT-002 | 1 | Block 198.51.100.23 at the egress firewall and VPN | approved | lena.weber |
| ACT-003 | 1 | Revoke sessions and force a password reset for k.novak | pending | - |
| ACT-004 | 2 | Disable access keys of ci-deployer | pending | lena.weber |
| ACT-005 | 2 | Detach AdministratorAccess granted during the incident | approved | lena.weber, omar.haddad |
| ACT-006 | 1 | Block 198.51.100.77 at the egress firewall and VPN | pending | - |
| ACT-007 | 0 | Pull storage access logs and list the objects read | auto_approved | policy:tier0 |
| ACT-008 | 1 | Revoke active sessions of role/DataEngineer | pending | - |

### INC-002: initial access -\> execution -\> credential access -\> lateral movement -\> command and control around fin-ws-22

5 related alert\(s\) between 2026-11-17T07:58:44Z and 2026-11-17T09:12:03Z. Progression: initial-access, execution, credential-access, lateral-movement, command-and-control. host: fin-ws-22, pay-app-02. user: a.okafor, svc\_payments. src ip: 10.20.3.22. dest ip: 203.0.113.66. domain: invoice-portal.example.net, cdn-kestrel-updates.example.org.

| Time (UTC) | Alert | Rule | Verdict | p | Techniques |
|---|---|---|---|---|---|
| 07:58:44 | ALT-3107 | MAIL-URL-CLICK | malicious | 0.95 | T1566.002 |
| 08:01:09 | ALT-3108 | EDR-OFFICE-CHILD-SHELL | malicious | 0.99 | T1204.002, T1059.001 |
| 08:05:30 | ALT-3109 | NDR-BEACON | malicious | 1.00 | T1071.001 |
| 08:41:12 | ALT-3110 | EDR-LSASS-ACCESS | malicious | 0.92 | T1003.001 |
| 09:12:03 | ALT-3111 | EDR-REMOTE-EXEC | malicious | 0.97 | T1021.002, T1569.002 |

**Why:**
- ALT-3107: invoice-portal.example.net is known malicious \(phishing, credential-harvest\) (+2.2, EV-040); 30% false-positive rate over 140 firings in 90 days (+0.6, EV-037); similar to PIR-2025-031 \(malicious\): PIR-2025-031: Loader delivered through a fake invoice portal (+0.6, PIR-2025-031)
- ALT-3108: cdn-kestrel-updates.example.org is known malicious \(payload-hosting, typosquat\) (+2.0, EV-046); 4% false-positive rate over 7 firings in 90 days (+1.4, EV-043); Office application spawned a script interpreter is a high-severity rule (+1.0, EV-043)
- ALT-3109: 9f2b5c1e7a4d3b8c6e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d is known malicious \(nightowl-loader, dll\) (+2.4, EV-053); 203.0.113.66 is known malicious \(c2, nightowl-loader\) (+2.2, EV-051); 10% false-positive rate over 15 firings in 90 days (+1.2, EV-049)
- ALT-3110: 5% false-positive rate over 11 firings in 90 days (+1.4, EV-055); Process read access to LSASS memory is a high-severity rule (+1.0, EV-055); similar to PIR-2025-031 \(malicious\): PIR-2025-031: Loader delivered through a fake invoice portal (+0.6, PIR-2025-031)
- ALT-3111: svc\_payments is only expected on pay-app-02, pay-db-01, used from fin-ws-22 (+1.5, EV-062); 15% false-positive rate over 20 firings in 90 days (+1.1, EV-060); Remote service execution \(PsExec-style\) is a high-severity rule (+1.0, EV-060)

**Correlated via:** ALT-3107↔ALT-3108 (a.okafor, fin-ws-22); ALT-3107↔ALT-3109 (fin-ws-22); ALT-3107↔ALT-3110 (a.okafor, fin-ws-22); ALT-3107↔ALT-3111 (fin-ws-22); ALT-3108↔ALT-3109 (fin-ws-22); ALT-3108↔ALT-3110 (a.okafor, fin-ws-22); ALT-3108↔ALT-3111 (fin-ws-22); ALT-3109↔ALT-3110 (fin-ws-22)

| Action | Tier | Proposed step | Decision | Approvers |
|---|---|---|---|---|
| ACT-009 | 0 | Open a case for INC-002 and preserve evidence | auto_approved | policy:tier0 |
| ACT-010 | 1 | Block invoice-portal.example.net at DNS and the web proxy | pending | - |
| ACT-011 | 1 | Isolate fin-ws-22 from the network with EDR containment | approved | omar.haddad |
| ACT-012 | 1 | Block cdn-kestrel-updates.example.org at DNS and the web proxy | pending | - |
| ACT-013 | 1 | Block 203.0.113.66 at the egress firewall and VPN | pending | - |
| ACT-014 | 1 | Revoke sessions and force a password reset for a.okafor | pending | - |
| ACT-015 | 2 | Rotate credentials of service account svc\_payments | pending | - |
| ACT-016 | 2 | Isolate pay-app-02 from the network with EDR containment | denied | - |

## Dismissed as expected activity

| Alert | Rule | p | Main reason |
|---|---|---|---|
| ALT-3101 | DLP-BULK-EXPORT | 0.01 | covered by CHG-4502: Nightly partner SFTP export window |
| ALT-3103 | EDR-SCHEDULED-TASK | 0.01 | covered by CHG-4471: Nightly cache-prune scheduled task for CI runners |
| ALT-3106 | EDR-NEW-SERVICE | 0.01 | covered by CHG-4489: Vendor kiosk software update \(VendorUpdater service\) |
| ALT-3112 | IDP-IMPOSSIBLE-TRAVEL | 0.02 | every external indicator is known benign |
| ALT-3113 | EDR-SCHEDULED-TASK | 0.01 | covered by CHG-4471: Nightly cache-prune scheduled task for CI runners |

## Approval policy

Tier 0 (investigate) is automatic, tier 1 (reversible containment) needs one analyst, tier 2 (disruptive or business-critical) needs two different analysts. Nothing is executed by TriageHive.

Audit trail: `audit.jsonl` (hash-chained, verify with `python -m triagehive verify-audit`).
