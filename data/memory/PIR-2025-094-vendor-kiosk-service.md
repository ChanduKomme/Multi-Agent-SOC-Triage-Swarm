# PIR-2025-094: Vendor update installs a service on a kiosk
verdict: benign | severity: low | techniques: T1543.003

A new service appeared on a lobby kiosk overnight. It was signed by the kiosk vendor, pulled from the vendor update
domain and matched an approved facilities change.

Resolution: closed. Lesson: low-criticality kiosk changes inside an approved window with vendor-signed binaries are
routine; an unsigned service or an unknown download source would not be.
