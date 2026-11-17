# INC-2025-0088 — Bulk analytics export (false positive)

**Closed:** 2025-04-02 | **Final severity:** Informational | **Confirmed:** False positive

## Pattern
DLP flagged a 40k-row customer report exported from the analytics console. The user was a
member of the growth-analytics group, the export ran during business hours, and the same
user had performed comparable exports monthly for a year.

## Lesson
Bulk-export DLP alerts from users whose role legitimately includes reporting are the single
largest false-positive source in this environment. Check group membership and 90-day
baseline before escalating. Do not auto-close if the export is paired with unusual auth or
egress activity on the same account.
