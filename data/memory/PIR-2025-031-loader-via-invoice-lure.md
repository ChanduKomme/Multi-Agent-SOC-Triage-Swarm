# PIR-2025-031: Loader delivered through a fake invoice portal
verdict: malicious | severity: critical | techniques: T1566.002, T1204.002, T1059.001, T1071.001, T1003.001

A finance user followed an invoice link, opened a macro document and Word launched an encoded PowerShell command.
Within minutes the laptop beaconed to a hosting provider every sixty seconds. Forty minutes later the operator read
LSASS memory with a renamed dump tool and reused a service-account hash to reach a payments server.

What worked: isolating the laptop before the remote execution step, rotating the service account, and blocking the
payload domain at the proxy. Lesson: treat Office-spawned shells on finance laptops as critical until proven otherwise.
