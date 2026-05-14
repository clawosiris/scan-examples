## 1. Spec and interface design

- [ ] 1.1 Define the Rust library + CLI boundary and the subprocess contract used by Python.
- [ ] 1.2 Define the default-vs-optional behavior: Rust path is primary, Python enrichment remains available as a readable fallback/reference path.
- [ ] 1.3 Define the large-input processing approach for 500k+ results.

## 2. Rust implementation

- [ ] 2.1 Add a Rust crate/workspace for enrichment logic and CLI entrypoint.
- [ ] 2.2 Implement selective VT metadata loading keyed by OID.
- [ ] 2.3 Implement selective Notus advisory loading keyed by OID, including rich advisory + product record merging.
- [ ] 2.4 Implement CVE extraction and optional SCAP/NVD metadata expansion.
- [ ] 2.5 Implement a two-pass or equivalently memory-conscious result-processing pipeline.

## 3. Python integration

- [ ] 3.1 Update the Python enrichment path to call the Rust CLI subprocess by default.
- [ ] 3.2 Keep the current Python implementation available as an explicit optional path for learning/debugging/fallback use.
- [ ] 3.3 Preserve current JSON output shape, field names, and CLI/e2e UX.

## 4. Verification

- [ ] 4.1 Update unit tests to cover the Rust-backed path and optional Python path selection.
- [ ] 4.2 Update the existing e2e path so it uses the Rust implementation under the hood.
- [ ] 4.3 Add at least one large-input validation/benchmark path for the streaming design.
- [ ] 4.4 Run the full test suite and relevant Rust checks.
