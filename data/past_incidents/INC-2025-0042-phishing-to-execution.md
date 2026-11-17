# INC-2025-0042 — Phishing to macro-driven PowerShell execution

**Closed:** 2025-02-09 | **Final severity:** High | **Confirmed:** True positive

## Pattern
A user clicked a look-alike SSO domain and submitted credentials. Roughly 30 minutes later
EDR observed `WINWORD.EXE` spawning `powershell.exe` with a base64 `-enc` command on the
same laptop. A persistence artifact (a per-30-minute scheduled task pointing at a binary in
`C:\Users\Public`) appeared the same afternoon.

## Correlation rule that helped
Same-host + same-user chains that move email -> execution -> persistence should be treated
as one incident, not three. Severity is driven by the persistence step, not the click.

## Response actions taken
Reset the user's password and revoked refresh tokens, removed the scheduled task, submitted
the dropped binary for analysis, and ran a mail-wide search-and-purge for the phishing
sender.
