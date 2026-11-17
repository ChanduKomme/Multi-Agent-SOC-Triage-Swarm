# PIR-2025-058: Stolen CI key used to grant cloud administrator rights
verdict: malicious | severity: critical | techniques: T1078, T1098.003, T1530

An access key for the CI deployment user was used from a VPS instead of the build runner. The attacker attached an
administrator policy to a data role, assumed it and downloaded a large share of a storage bucket.

What worked: detaching the policy, disabling the key and revoking role sessions. Lesson: the CI identity should only
act from build runners; any call from elsewhere is a credential-theft signal, even if the API calls look routine.
