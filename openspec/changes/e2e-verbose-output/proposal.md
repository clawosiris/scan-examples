## Why

The current `e2e` workflow only emits the final JSON payload. That is machine-friendly, but it leaves humans blind while the scan is running and does not summarize how many findings the target produced.

Issue #4 asks for two improvements:
- visible progress for each major lifecycle step in logs
- summary stats for the issues found against the target container

Without those, CI logs are harder to debug and operators have to inspect raw results just to answer basic questions like whether the scan produced any findings.

## What Changes

- Add step-by-step progress logging for the `e2e` lifecycle.
- Include a findings summary in the e2e result payload with total issue count and grouped stats.
- Document the new verbose behavior in the repo README.
- Add tests covering findings-summary generation and progress logging hooks.

## Impact

- Makes long-running e2e scans easier to follow in CI and local runs.
- Preserves machine-readable output while adding human-usable diagnostics.
- Gives quick visibility into how many findings the target scan produced.
