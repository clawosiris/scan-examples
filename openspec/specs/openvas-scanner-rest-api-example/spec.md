## ADDED Requirements

### Requirement: Python example for OpenVAS Scanner REST API
The repository SHALL provide runnable Python example code that demonstrates use of the OpenVAS Scanner container REST API against the community container distribution.

#### Scenario: Example targets community scanner deployment
- **GIVEN** a user follows this repository to run the example
- **WHEN** they inspect the example entrypoint and configuration
- **THEN** the example identifies the community scanner container setup as the supported environment
- **AND** documents any required endpoints, certificates, environment variables, and the default target TCP port used by the bundled e2e flow.

### Requirement: Full & Fast configuration conversion
The repository SHALL provide a reproducible way to convert the community feed's **Full & Fast** scan configuration into the JSON payload format expected by the scanner REST API using `scannerctl`.

#### Scenario: Convert feed configuration for API submission
- **GIVEN** the community feed data and `scannerctl` are available in the test or runtime environment
- **WHEN** the conversion step is executed for the Full & Fast scan configuration
- **THEN** the repository produces JSON suitable for inclusion in the `vts` portion of a scan-creation request
- **AND** the conversion step is documented or scripted so users do not need to reverse-engineer it.

### Requirement: Scan lifecycle example coverage
The Python example SHALL cover the documented scan lifecycle operations for the scanner REST API.

#### Scenario: Create a scan
- **GIVEN** a reachable scanner API and converted Full & Fast configuration
- **WHEN** the example creates a scan
- **THEN** it sends a `POST /scans` request containing a target definition and converted scan configuration
- **AND** it captures the returned scan identifier for later operations.

#### Scenario: Start a scan
- **GIVEN** an existing scan identifier
- **WHEN** the example starts the scan
- **THEN** it sends the appropriate action request to the scanner API
- **AND** reports success or failure in a user-visible way.

#### Scenario: Stop a scan
- **GIVEN** a running or scheduled scan identifier
- **WHEN** the example stops the scan
- **THEN** it sends the appropriate action request to the scanner API
- **AND** reports success or failure in a user-visible way.

#### Scenario: Get scan results
- **GIVEN** a created scan identifier
- **WHEN** the example fetches results
- **THEN** it requests scan results from the scanner API
- **AND** exposes returned results in a stable machine-readable format for automation and tests.

#### Scenario: Delete a scan
- **GIVEN** a created scan identifier
- **WHEN** the example deletes the scan
- **THEN** it sends the delete request to the scanner API
- **AND** confirms cleanup success or reports the failure.

### Requirement: Example container image
The repository SHALL provide a Docker image for running the example code consistently.

#### Scenario: Build example container
- **GIVEN** the repository source tree
- **WHEN** the example container image is built
- **THEN** the image contains the Python runtime, example code, and any required helper tooling
- **AND** exposes a documented command or entrypoint for running the example workflow.

### Requirement: Docker Compose end-to-end environment
The repository SHALL provide a Docker Compose based environment for validating the example workflow end to end.

#### Scenario: Compose environment includes scanner and target
- **GIVEN** a developer or CI runner launches the repository's e2e environment
- **WHEN** the compose stack starts
- **THEN** it includes the community scanner/feed setup
- **AND** a lightweight HTTP target container as the scan target
- **AND** the default bundled scan target definition points at TCP port 80 for that HTTP service
- **AND** any supporting services required for the example and test flow.

### Requirement: End-to-end test coverage
The repository SHALL include an end-to-end test that exercises the documented workflow against the Compose environment.

#### Scenario: e2e test runs lifecycle workflow
- **GIVEN** the compose environment is running
- **WHEN** the e2e test executes
- **THEN** it performs Full & Fast configuration conversion
- **AND** logs the major lifecycle steps in a human-readable way while the workflow is running
- **AND** creates, starts, stops, retrieves results for, and deletes a scan
- **AND** writes the lifecycle result payload in a stable machine-readable JSON format for automation and debugging
- **AND** includes summary stats for the number of findings returned by the scan
- **AND** fails if any lifecycle step cannot be completed.

### Requirement: Repository licensing
The repository SHALL declare a permissive license suitable for both proprietary and open-source reuse of the example code.

#### Scenario: Repository publishes MIT license
- **GIVEN** a consumer evaluates whether the example code can be reused
- **WHEN** they inspect the repository metadata and top-level files
- **THEN** the repository includes an MIT `LICENSE` file
- **AND** the README and package metadata identify the project as MIT-licensed.

### Requirement: GitHub Actions workflow for validation
The repository SHALL provide a GitHub Actions workflow that validates the example in CI.

#### Scenario: CI builds and runs e2e workflow
- **GIVEN** a push or pull request that changes the example, container, or test assets
- **WHEN** the GitHub Actions workflow runs
- **THEN** it builds the example container
- **AND** starts the Docker Compose test environment
- **AND** runs the e2e test
- **AND** preserves logs or artifacts sufficient to debug failures.
