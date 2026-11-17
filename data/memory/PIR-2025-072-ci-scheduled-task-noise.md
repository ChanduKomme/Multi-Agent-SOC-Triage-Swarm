# PIR-2025-072: Scheduled task alerts from CI runners
verdict: benign | severity: low | techniques: T1053.005

The scheduled-task rule fires on every runner rebuild because the image registers a cache-prune task. The task
binary is signed, matches the approved change and runs as svc_ci.

Resolution: tuned. Lesson: scheduled tasks on build runners under an approved change are expected; a task created by
an interactive user or pointing to a temp folder is not.
