# INC-2024-0117 — Service account credential theft on payments tier

**Closed:** 2024-11-17 | **Final severity:** Critical | **Confirmed:** True positive

## Pattern
An EDR alert fired for `procdump64.exe` obtaining a `PROCESS_VM_READ` handle on `lsass.exe`
on a payments application host. Within 20 minutes the same service account authenticated
from a foreign ASN, then a multi-gigabyte HTTPS POST left the host to a newly registered
domain.

## Root cause
A build agent had cached a long-lived service-account secret. The attacker dumped LSASS,
recovered the token, and reused it from outside the corporate network.

## What worked
Correlating EDR credential-access alerts with identity impossible-travel events inside a
30-minute window collapsed 3 noisy medium alerts into one critical incident.

## Response actions taken
Isolated the host, revoked and rotated the service-account credential, blocked the
exfiltration domain at the proxy, forced re-auth for all sessions of that principal.
