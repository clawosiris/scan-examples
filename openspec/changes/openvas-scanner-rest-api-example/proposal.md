## Why

`scan-examples` currently documents the intended OpenVAS DETECT workflow in `scan-docs.md`, but it does not provide runnable example code for the OpenVAS Scanner container REST API. Issue #1 asks for a concrete Python example, containerization for the example itself, and an end-to-end test environment that exercises the documented lifecycle against a real target.

Without that example, consumers must translate documentation into implementation on their own, which raises onboarding cost and makes regressions in the documented workflow hard to detect.

## What Changes

- Add Python example code that uses the OpenVAS Scanner REST API against the community container.
- Include logic and example assets for converting the community feed's **Full & Fast** scan configuration into the JSON format required by the scanner REST API via `scannerctl`.
- Support the documented scan lifecycle:
  - create scan
  - start scan
  - stop scan
  - fetch results
  - delete scan
- Add a Docker image for running the example code consistently.
- Add a Docker Compose based end-to-end environment using:
  - community scanner/feed setup
  - a target metasploitable container
  - any supporting services required to run the example and tests
- Add an end-to-end test that executes the above lifecycle in the composed environment.
- Add a GitHub Actions workflow that builds the environment and runs the end-to-end test.

## Impact

- Establishes the repo's first runnable example implementation.
- Turns `scan-docs.md` from reference-only documentation into a verifiable contract.
- Adds CI coverage for the documented OpenVAS Scanner REST API workflow.
