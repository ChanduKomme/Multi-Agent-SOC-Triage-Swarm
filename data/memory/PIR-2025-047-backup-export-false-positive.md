# PIR-2025-047: Nightly backup export flagged as exfiltration
verdict: benign | severity: low | techniques: T1567

The DLP rule fired on svc_backup exporting several gigabytes to the partner SFTP host at 01:40. The transfer matched
the approved nightly window and the allowlisted partner address. No interactive logon was involved.

Resolution: closed as expected behaviour. Lesson: check the change calendar and destination reputation before
escalating bulk exports from the backup service account; escalate only outside the window or to a new destination.
