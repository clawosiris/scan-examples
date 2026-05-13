## ADDED Requirements

### Requirement: Authenticated SSH e2e scan
The repository SHALL configure the bundled metasploitable e2e target and scan payload so the default e2e flow can perform authenticated SSH checks.

#### Scenario: Compose target has a known SSH password
- **GIVEN** the Docker Compose e2e environment is started
- **WHEN** the metasploitable target container starts
- **THEN** it sets the `msfadmin` password to a documented value
- **AND** starts the SSH service.

#### Scenario: e2e payload includes SSH credentials
- **GIVEN** the e2e command converts the scan configuration for the bundled target
- **WHEN** no SSH credential override is provided
- **THEN** the scan target payload includes SSH username/password credentials for `msfadmin` on port `22`.

#### Scenario: SSH credentials are configurable
- **GIVEN** a caller provides alternate SSH username, password, or port values via CLI flags or environment variables
- **WHEN** the scan configuration is converted
- **THEN** the scan target payload uses those supplied SSH credential values.
