## ADDED Requirements

### Requirement: Python example for OpenVAS Scanner REST API
The repository SHALL provide runnable Python example code that demonstrates use of the OpenVAS Scanner container REST API against the community container distribution.

#### Scenario: Example targets community scanner deployment
- **GIVEN** a user follows this repository to run the example
- **WHEN** they inspect the example entrypoint and configuration
- **THEN** the example identifies the community scanner container setup as the supported environment
- **AND** documents the required endpoints, feed mounts, environment variables, and default target TCP port set used by the bundled e2e flow
- **AND** explains the `ospd-openvas` dependency needed for scans to start successfully in the community container stack.

### Requirement: Scan configuration selection
The repository SHALL provide reproducible ways to build scanner REST API scan payloads from either community feed scan configurations converted with `scannerctl` or a custom scanner API JSON payload.

#### Scenario: Convert feed configuration for API submission
- **GIVEN** the community feed data and `scannerctl` are available in the test or runtime environment
- **WHEN** the conversion step is executed for a named feed scan configuration
- **THEN** the repository produces JSON suitable for inclusion in the `vts` portion of a scan-creation request
- **AND** the conversion step is documented or scripted so users do not need to reverse-engineer it.

#### Scenario: Load custom scanner API scan configuration
- **GIVEN** a custom scanner API scan config JSON payload, or a zip archive containing one JSON payload
- **WHEN** the e2e workflow is configured to use it
- **THEN** the workflow uses that payload instead of running `scannerctl`
- **AND** replaces the target hosts with the requested e2e hosts
- **AND** injects configured SSH credentials into the target definition
- **AND** preserves the payload's own target ports unless an explicit TCP port override is provided.

### Requirement: Scan lifecycle example coverage
The Python example SHALL cover the documented scan lifecycle operations for the scanner REST API and make long-running scans observable enough for local runs and CI debugging while exposing enriched results that are useful for automation and post-scan inspection.

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
- **GIVEN** a created scan identifier and the mounted Greenbone vulnerability-test feed
- **WHEN** the example fetches results
- **THEN** it requests scan results from the scanner API
- **AND** retries result polling until findings appear or a configured timeout is reached
- **AND** preserves the raw scanner results in a stable machine-readable format for automation and tests
- **AND** enriches results that include an OID with metadata from `vt-metadata.json` when that metadata is available.

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
- **AND** an `ospd-openvas` service with the scanner socket wiring required by `openvasd`
- **AND** a `kirscht/metasploitable3-ub1404` multi-service target container as the scan target
- **AND** the default bundled scan target definition points at TCP ports `21,22,80,139,445,3306`
- **AND** any supporting services required for the example and test flow.

### Requirement: Feed-based result enrichment
The repository SHALL provide example code that expands scanner results with metadata from the Greenbone feed.

#### Scenario: Enrich result by VT OID
- **GIVEN** a scanner result containing an OID present in `vt-metadata.json`
- **WHEN** the enrichment step processes that result
- **THEN** it looks up the matching VT metadata entry by OID
- **AND** includes useful metadata in the enriched output such as VT name, filename, family, category, references, and selected tags when available
- **AND** preserves the original scanner result fields at the enriched result entry top level
- **AND** adds enrichment data directly to each result entry rather than wrapping the raw result in
  a separate `result` object.

#### Scenario: Enrich result by CVE from optional SCAP data
- **GIVEN** a scanner result whose matched VT metadata references one or more CVE IDs
- **AND** SCAP/NVD CVE JSON data is configured
- **WHEN** the enrichment step processes that result
- **THEN** it looks up the referenced CVE IDs in the SCAP CVE index
- **AND** includes useful CVE metadata such as descriptions, timestamps, references, weaknesses, CVSS metrics, and affected CPEs when available
- **AND** marks whether CVE metadata was matched, partially matched, unavailable, or not found.

#### Scenario: Result has no matching VT metadata
- **GIVEN** a scanner result whose OID is missing from the local VT metadata index or is absent entirely
- **WHEN** the enrichment step processes that result
- **THEN** it does not fail the whole workflow solely because enrichment data is missing
- **AND** preserves the original scanner result fields at the enriched result entry top level
- **AND** marks the metadata lookup as unavailable or omitted in a consistent way.

#### Scenario: VT metadata payload is unreadable
- **GIVEN** the local `vt-metadata.json` file exists but cannot be parsed or has an unsupported structure
- **WHEN** the CLI attempts to load enrichment data
- **THEN** it continues without enrichment instead of failing the whole command
- **AND** emits a brief user-visible message that enrichment was skipped.

#### Scenario: SCAP data is unavailable or unreadable
- **GIVEN** optional SCAP enrichment is configured but the local SCAP data is missing, unreadable, or malformed
- **WHEN** the CLI attempts to load CVE enrichment data
- **THEN** it continues with VT metadata enrichment instead of failing the whole command
- **AND** emits a brief user-visible message that CVE enrichment was skipped.

### Requirement: End-to-end test coverage
The repository SHALL include an end-to-end test that exercises the documented workflow against the Compose environment.

#### Scenario: e2e test runs lifecycle workflow
- **GIVEN** the compose environment is running
- **WHEN** the e2e test executes
- **THEN** it prepares a scan payload from either a scannerctl-converted feed config or a custom JSON config
- **AND** logs the major lifecycle steps in a human-readable way while the workflow is running
- **AND** pretty-prints enriched findings in the CI or terminal log
- **AND** creates, starts, retrieves results for, and deletes a scan
- **AND** supports a quick mode that stops the scan after initial findings are available
- **AND** supports a configurable minimum result count before stopping in quick mode
- **AND** supports a full mode that keeps polling until the scan reaches `succeeded` instead of stopping at initial findings
- **AND** writes the lifecycle result payload in a stable machine-readable JSON format for automation and debugging
- **AND** includes both raw `results` and `enriched_results`
- **AND** keeps each `enriched_results` entry shaped like the original scanner result with added
  enrichment fields
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
- **AND** uses the bundled custom scan config JSON archive as the default e2e scan config
- **AND** runs the e2e test in quick completion mode for pull requests and non-main pushes
- **AND** runs the e2e test in full scan-completion mode for pushes to `main`
- **AND** preserves logs or artifacts sufficient to debug failures.

### Requirement: Feed synchronization via greenbone-feed-sync
The repository SHALL synchronize required Greenbone feed content with `greenbone-feed-sync` instead of
relying on dedicated community feed data-copy containers.

#### Scenario: Compose synchronizes required feed data
- **GIVEN** a developer or CI runner prepares the e2e Compose environment
- **WHEN** feed synchronization is run
- **THEN** the Compose environment uses the
  `registry.community.greenbone.net/community/greenbone-feed-sync` container
- **AND** synchronizes NASL vulnerability tests, Notus data, and GVMD data objects
- **AND** stores the synchronized data in persistent Docker named volumes reused by `ospd-openvas`,
  `openvasd`, and the example CLI
- **AND** does not require the `vulnerability-tests`, `notus-data`, or `data-objects` feed data-copy services.

#### Scenario: CI reuses synchronized feed volumes
- **GIVEN** the self-hosted e2e GitHub Actions workflow runs repeatedly
- **WHEN** the workflow prepares feed data
- **THEN** it runs the feed-sync Compose service before starting the scanner stack
- **AND** preserves the feed volumes during teardown so later runs can fetch feed deltas instead of repopulating the feeds from scratch.
