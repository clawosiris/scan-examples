## ADDED Requirements

### Requirement: Released mock-server artifact for fast validation
The repository SHALL use a released `openvas-mock-scanner` artifact for
mock-backed CI validation instead of a floating image tag.

#### Scenario: Mock-backed CI uses a stable released artifact
- **GIVEN** the repository runs mock-backed compatibility checks in CI
- **WHEN** the workflow resolves the mock-server image to run
- **THEN** it uses a stable released artifact identified by version tag, digest,
  or another reproducible release reference
- **AND** it does not use an unqualified moving `:latest` tag
- **AND** the selected artifact is documented so future updates are intentional.

### Requirement: Feed-derived mock compatibility coverage
The repository SHALL validate its mock-backed scan workflow using realistic
data derived from the Greenbone feed inputs already used by the real scan path.

#### Scenario: Mock tests use realistic feed-derived result data
- **GIVEN** the repository already uses Greenbone feed data as part of the real
  scan flow
- **WHEN** mock-backed compatibility tests are prepared
- **THEN** the test data is generated from or derived from those existing feed
  inputs instead of relying only on a trivial canned happy-path payload
- **AND** the resulting test cases reflect realistic OIDs, metadata, and result
  structures that `scan_examples` is expected to consume.

#### Scenario: Mock tests validate client-relevant result handling
- **GIVEN** the mock-backed compatibility tests run against the released mock
  server artifact
- **WHEN** the repository exercises the scan lifecycle and result retrieval path
- **THEN** the tests verify the behaviors this repository depends on, including
  result parsing, feed-derived metadata expectations, and larger or paged
  result handling where applicable
- **AND** the mock-backed path remains fast enough to serve as the default
  short-path CI gate.

### Requirement: Real-scan coverage for high-signal branches and releases
The repository SHALL keep the heavyweight real-scan path in CI for pull
requests targeting `main` and for release-oriented validation flows, in
addition to the fast mock-backed checks.

#### Scenario: PR to main runs both fast and heavyweight validation
- **GIVEN** a pull request targets the `main` branch
- **WHEN** the repository CI runs for that pull request
- **THEN** it runs the fast mock-backed validation path
- **AND** it also runs the real-scan validation path
- **AND** the real-scan path is not the only validation signal for that pull
  request.

#### Scenario: Release validation runs both fast and heavyweight validation
- **GIVEN** a release workflow or release-oriented pull request is validated
- **WHEN** the repository CI runs for that release validation path
- **THEN** it runs the fast mock-backed validation path
- **AND** it also runs the real-scan validation path
- **AND** the release signal reflects both deterministic mock compatibility and
  the real scanner integration.

#### Scenario: General pull requests keep the fast validation default
- **GIVEN** a general pull request or short-lived iteration path that does not
  target `main` and is not a release validation flow
- **WHEN** CI runs
- **THEN** the fast mock-backed validation path is the default scanner-facing
  gate
- **AND** the heavyweight real-scan path is not required for every such run.
