## 1. Mock artifact policy

- [x] 1.1 Replace the floating mock image reference with a released
      `openvas-mock-scanner` version tag or digest.
- [x] 1.2 Document how the chosen mock release is selected and updated.

## 2. Higher-value mock compatibility coverage

- [x] 2.1 Add mock-backed tests that use realistic feed-derived data rather than
      only the `success-basic` path.
- [x] 2.2 Cover the client/result behaviors that matter to this repository, such
      as metadata lookup expectations, result payload shape, and larger or
      paged result handling when applicable.
- [x] 2.3 Keep the mock-backed path fast enough to remain the default short-path
      CI gate.

## 3. Real-scan gating policy

- [x] 3.1 Run real-scan validation in addition to the mock-backed path for pull
      requests targeting `main`.
- [x] 3.2 Run real-scan validation in addition to the mock-backed path for
      release validation flows.
- [x] 3.3 Ensure general PRs and short-lived iteration paths continue to use the
      fast mock-backed validation by default.

## 4. Verification

- [x] 4.1 Add or update tests for the new mock compatibility coverage.
- [x] 4.2 Update CI/workflow documentation to describe the fast-path and
      high-signal-path split.
