## CHANGED Requirements

### Requirement: Feed-based result enrichment
The repository SHALL provide example code that expands scanner results with metadata from the Greenbone feed while keeping the current enriched JSON shape stable.

#### Scenario: Rust engine performs primary enrichment path
- **GIVEN** scanner result JSON plus local feed data for VT metadata and/or Notus advisories
- **WHEN** the default enrichment path runs
- **THEN** the repository uses the Rust enrichment engine as the primary implementation
- **AND** preserves the current enriched JSON field names and top-level result shape already documented by the repository
- **AND** supports VT metadata, Notus metadata, and optional SCAP/NVD CVE enrichment.

#### Scenario: Python engine remains available as an optional reference path
- **GIVEN** a developer or user wants to inspect or debug the enrichment flow without using Rust
- **WHEN** they explicitly select the Python implementation
- **THEN** the repository still provides the current Python enrichment path as an optional/reference implementation
- **AND** it produces the same enriched JSON structure as the default Rust-backed path.

#### Scenario: Notus-backed results preserve merged advisory behavior
- **GIVEN** a Notus OID present in both sparse product-scoped `.notus` files and richer advisory aggregate `.notus` files
- **WHEN** the enrichment step processes that result
- **THEN** it prefers the richer advisory-style metadata
- **AND** merges complementary fixed-package/product details from the product-scoped records.

#### Scenario: Large result sets use selective feed-metadata lookup by OID
- **GIVEN** a scan result file that may contain many result entries
- **WHEN** the default enrichment path runs
- **THEN** it selectively loads only the VT/Notus/SCAP metadata needed for the OIDs and CVEs present in the result set
- **AND** it does not claim a fully streaming result-processing pipeline in the current implementation.

### Requirement: Scan lifecycle example coverage
The Python example SHALL continue to cover the documented scan lifecycle operations for the scanner REST API while using the default enrichment engine under the hood.

#### Scenario: Existing e2e workflow uses Rust-backed enrichment
- **GIVEN** the repository e2e workflow retrieves scan results
- **WHEN** enrichment is applied during the existing e2e path
- **THEN** the e2e path uses the Rust-backed enrichment engine under the hood by default
- **AND** keeps the current CLI-facing workflow and output contract stable for users and tests.
