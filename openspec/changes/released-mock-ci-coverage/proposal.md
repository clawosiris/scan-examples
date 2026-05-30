## Why

Issue #46 calls out two problems in the current CI split.

First, the mock-backed check is not deterministic enough because it pulls a
floating `ghcr.io/clawosiris/openvas-mock-scanner:latest` image. That means a
`scan-examples` pull request can fail because the mock server changed out from
under it, not because the repository itself regressed.

Second, the current mock coverage is too shallow. The existing smoke test only
exercises the `success-basic` path and does not validate the more realistic
result shapes that matter to this repository, especially the feed-derived
metadata and result payload structure the real scan path already relies on.

At the same time, the real scan remains the highest-value compatibility signal,
but it is too expensive to run as the default short-path gate for every quick
iteration.

## What Changes

- Replace the floating mock image dependency with a released
  `openvas-mock-scanner` artifact identified by a stable version tag or digest.
- Expand mock-backed validation beyond a basic liveness check by adding
  compatibility tests that use realistic data derived from the Greenbone feed
  inputs already used by the real scan flow.
- Keep mock-backed validation as the default fast gate for short-lived and
  general pull requests.
- Run the real scan path in addition to the mock-backed checks for pull requests
  targeting `main` and for release-oriented validation flows.
- Document the CI split so contributors understand which paths are expected to
  run for quick validation versus higher-cost release confidence.

## Impact

- CI becomes more reproducible because the mock dependency stops drifting with a
  floating tag.
- Mock validation becomes a meaningful compatibility test instead of only a
  container smoke check.
- Heavyweight real-scan coverage is preserved where it matters most without
  forcing every short-lived PR to pay that cost.
