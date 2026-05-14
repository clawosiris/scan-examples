## 1. Spec and interface design

- [x] 1.1 Define the Rust library + CLI boundary and the subprocess contract used by Python.
- [x] 1.2 Define the default-vs-optional behavior: Rust path is primary, Python enrichment remains available as a readable fallback/reference path.
- [x] 1.3 Document the shipped large-input behavior accurately: selective feed-metadata lookup by OID landed; full result streaming did not.

## 2. Rust implementation

- [x] 2.1 Add a Rust crate/workspace for enrichment logic and CLI entrypoint.
- [x] 2.2 Implement selective VT metadata loading keyed by OID.
- [x] 2.3 Implement selective Notus advisory loading keyed by OID, including rich advisory + product record merging.
- [x] 2.4 Implement CVE extraction and optional SCAP/NVD metadata expansion.
- [ ] 2.5 Implement a true streaming or otherwise full-result memory-conscious pipeline for very large scan-results payloads.

## 3. Python integration

- [x] 3.1 Update the Python enrichment path to call the Rust CLI subprocess by default.
- [x] 3.2 Keep the current Python implementation available as an explicit optional path for learning/debugging/fallback use.
- [x] 3.3 Preserve current JSON output shape, field names, and CLI/e2e UX.

## 4. Verification

- [x] 4.1 Update unit tests to cover the Rust-backed path and optional Python path selection.
- [x] 4.2 Update the existing e2e path so it uses the Rust implementation under the hood.
- [ ] 4.3 Add a dedicated large-input benchmark or other repeatable scale-validation path beyond the current parity/unit/e2e checks.
- [x] 4.4 Run the full test suite and relevant Rust checks.
