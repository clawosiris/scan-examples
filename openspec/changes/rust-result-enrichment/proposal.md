## Why

Issue #28 asked to move scan-result enrichment into Rust while preserving the behavior already implemented in Python for issues #22 and #31.

That Rust-backed path is now implemented and merged, so this change record should describe what actually shipped rather than the original target shape.

## What Landed

- Added a Rust crate/workspace (`rust/scan-enrichment`) with both library code and a `scan-enrich-results` CLI.
- Added engine selection in Python (`auto`, `python`, `rust`), with Rust used by default when the binary is available.
- Kept the Python implementation available as an explicit reference/fallback path.
- Preserved the enriched JSON structure introduced by issues #22 and #31, including:
  - VT metadata enrichment from `vt-metadata.json`
  - Notus enrichment with advisory/product record merging
  - optional SCAP/NVD CVE metadata expansion
- Updated the Python CLI and e2e workflow so the default container-backed path uses Rust under the hood.
- Added parity fixtures/tests that compare Rust output against the Python reference implementation.

## What Did Not Land

- The Rust path selectively loads only the feed metadata needed for OIDs present in the result set, but it still loads the scan-results JSON payload into memory before enrichment.
- No separate large-input benchmark or streaming-output implementation was added in this iteration.

## Impact

- Default enrichment now runs through the Rust implementation in supported environments.
- The Python path remains available for readability, debugging, and fallback use.
- Docs/specs need to describe the shipped selective-lookup behavior accurately and should not claim full streaming or benchmark coverage that is not implemented yet.
