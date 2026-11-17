# TriageHive evaluation

## Regression suite (night-shift + generated scenarios)

| Metric | Value |
|---|---|
| Scenarios evaluated | 201 |
| Alerts (malicious / benign) | 2933 (983 / 1950) |
| Missed attacks (malicious dismissed) | 0 (0.00%) |
| Malicious verdict precision / recall | 0.990 / 0.954 |
| Noise closed without a human | 80.0% |
| Incident grouping P / R / F1 | 0.995 / 1.000 / 0.997 |
| Incident severity agreement | 99.7% |
| Steering probes / regressions | 983 / 0 |
| Unsafe approvals | 0 |
| Reviewer errors | 0 |
| Audit chains failing verification | 0 |
| Tool calls per alert | 5.62 |

## Hand-written holdouts (not gated on quality)

| Scenario | Checksum | Attacks missed | Routine closed | False alarms | Attack pairs grouped | Wrong pairs |
|---|---|---|---|---|---|---|
| weekend-shift | ok | 0/6 | 2/6 | ALT-7202, ALT-7203 | 2/2 | 0 |
| holiday-shift | ok | 0/7 | 2/5 | ALT-8307, ALT-8310 | 5/5 | 0 |

## Gate: PASSED

- all thresholds met

