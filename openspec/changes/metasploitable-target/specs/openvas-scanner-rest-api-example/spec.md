## CHANGED Requirements

### Requirement: Docker Compose end-to-end environment
The repository SHALL provide a Docker Compose based environment for validating the example workflow end to end.

#### Scenario: Compose environment includes metasploitable target
- **GIVEN** a developer or CI runner launches the repository's e2e environment
- **WHEN** the compose stack starts
- **THEN** it includes the community scanner/feed setup
- **AND** a `kirscht/metasploitable3-ub1404` container as the scan target
- **AND** any supporting services required for the example and test flow.

### Requirement: Target port defaults are documented and realistic
The repository SHALL provide a default bundled target port definition appropriate for the metasploitable target.

#### Scenario: Default port set includes SSH and common exposed services
- **GIVEN** the bundled e2e configuration for the metasploitable target
- **WHEN** a user inspects the example defaults
- **THEN** the documented default TCP port set includes SSH
- **AND** includes a reasonable set of additional service ports exposed by the target
- **AND** the same defaults are used consistently by the Compose environment, CLI examples, and docs.

### Requirement: End-to-end workflow remains observable on richer targets
The repository SHALL preserve clear lifecycle and findings output when scanning the metasploitable target.

#### Scenario: e2e workflow reports findings for metasploitable target
- **GIVEN** the metasploitable e2e environment is running
- **WHEN** the e2e test executes
- **THEN** it logs the major lifecycle steps in a human-readable way while the workflow is running
- **AND** writes the lifecycle result payload in a stable machine-readable JSON format for automation and debugging
- **AND** includes summary stats for the findings returned from the metasploitable target.
