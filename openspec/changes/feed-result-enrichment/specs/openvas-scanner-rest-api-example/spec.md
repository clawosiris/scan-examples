## CHANGED Requirements

### Requirement: Scan lifecycle example coverage
The Python example SHALL cover the documented scan lifecycle operations for the scanner REST API and expose results in a form that is useful for both automation and post-scan inspection.

#### Scenario: Get enriched scan results
- **GIVEN** a created scan identifier and the mounted Greenbone feed data
- **WHEN** the example fetches scan results
- **THEN** it requests scan results from the scanner API
- **AND** retries result polling until findings appear or a configured timeout is reached
- **AND** enriches each result that includes an OID with VT metadata from `vt-metadata.json`
- **AND** exposes the enriched results in a stable machine-readable JSON format for automation and tests.

### Requirement: Feed-based result enrichment
The repository SHALL provide example code that expands scanner results with metadata from the Greenbone feed.

#### Scenario: Enrich result by VT OID
- **GIVEN** a scanner result containing an OID present in `vt-metadata.json`
- **WHEN** the enrichment step processes that result
- **THEN** it looks up the matching VT metadata entry by OID
- **AND** includes useful metadata in the enriched output such as VT name, filename, family, category, references, and selected tags when available
- **AND** preserves the original scanner result fields alongside the enrichment data.

#### Scenario: Result has no matching VT metadata
- **GIVEN** a scanner result whose OID is missing from the local VT metadata index or is absent entirely
- **WHEN** the enrichment step processes that result
- **THEN** it does not fail the whole workflow solely because enrichment data is missing
- **AND** preserves the original scanner result in the output
- **AND** marks the metadata lookup as unavailable or omitted in a consistent way.

### Requirement: Human-readable enriched findings output
The repository SHALL make enriched findings easy to inspect during CI and local end-to-end runs.

#### Scenario: CI log shows pretty-printed enriched findings
- **GIVEN** the e2e workflow has retrieved scan results and applied feed enrichment
- **WHEN** the example runs in CI or a local terminal
- **THEN** it emits a readable pretty-printed view of the enriched findings to the log
- **AND** keeps the full enriched payload available as JSON for automation and debugging
- **AND** does not require users to manually open the raw artifact just to understand what was found.
