## Why

The current end-to-end setup uses a lightweight HTTP container on TCP port 80. That proves the scan lifecycle works, but it does not exercise the example against a more realistic multi-service target.

Issue #6 asks to use the `kirscht/metasploitable3-ub1404` container as the scan target and to scan a reasonable set of ports including SSH.

## What Changes

- Replace the current lightweight HTTP target in the Compose environment with the metasploitable container.
- Update the bundled target definition defaults to scan a reasonable TCP port set for the metasploitable target, including SSH.
- Document the chosen default ports and why they were selected.
- Update e2e validation so the workflow still emits clear findings output against the richer target.

## Impact

- Makes the example closer to a realistic vulnerable-target workflow.
- Increases confidence that the example handles a target with multiple exposed services.
- Likely increases scan/runtime cost, so CI and local docs need to reflect the heavier target.
