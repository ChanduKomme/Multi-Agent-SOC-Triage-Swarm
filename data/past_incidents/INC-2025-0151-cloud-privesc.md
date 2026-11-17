# INC-2025-0151 — Cloud IAM privilege escalation after token reuse

**Closed:** 2025-07-21 | **Final severity:** Critical | **Confirmed:** True positive

## Pattern
A stolen service-account session was used to call `AttachUserPolicy`, granting
`AdministratorAccess` to a newly created IAM user with a plausible-looking name
(`backup-svc-*`). Source IP belonged to the same hosting ASN seen in the earlier
impossible-travel sign-in.

## Correlation rule that helped
Any cloud IAM grant of an administrative policy from a source ASN that is not on the
corporate egress list is treated as Critical regardless of the raw alert severity, and is
linked to any identity anomaly for the same principal in the preceding 24 hours.

## Response actions taken
Detached the policy, deleted the rogue IAM user, revoked all sessions for the principal,
and opened a CloudTrail scope review for the ASN.
