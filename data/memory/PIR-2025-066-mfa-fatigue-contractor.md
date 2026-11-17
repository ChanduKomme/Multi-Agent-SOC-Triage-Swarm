# PIR-2025-066: MFA fatigue against a contractor account
verdict: malicious | severity: high | techniques: T1621, T1078

A contractor received more than a dozen push requests in ten minutes from an anonymising VPS. The user denied all of
them, but the same address later appeared against other identities, showing a password-spraying campaign.

What worked: blocking the source address and forcing a password reset. Lesson: correlate the source IP of push
bursts with other identity and cloud alerts in the following hours.
