# INC-2025-0244 — Scheduled task created by software deployment tool

**Closed:** 2025-11-12 | **Final severity:** Low | **Confirmed:** False positive

## Pattern
"Scheduled task created by non-admin" fires whenever the endpoint management agent stages
an update. Distinguishing signal: legitimate tasks point at binaries under
`C:\Program Files\` and are signed; malicious ones point at `C:\Users\Public\` or
`%TEMP%` and are unsigned.
