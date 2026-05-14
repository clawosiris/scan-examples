## Why

Issue #28 asks to move scan-result enrichment into Rust while preserving the behavior already implemented in Python for issues #22 and #31. The current Python enrichment path works, but it loads full result sets and feed metadata into Python objects, which is a bad fit for the 500k+ result scale called out in the issue.

We need a Rust implementation that:
- preserves the current enriched JSON shape and field names
- supports both NASL `vt-metadata.json` enrichment and Notus `.notus` enrichment
- can be invoked from the existing Python CLI/e2e flow as a subprocess
- is memory-conscious for very large result sets

## What Changes

- Add a Rust crate that exposes the enrichment logic as a library and a CLI frontend.
- Implement a two-pass enrichment pipeline that scans results for unique OIDs, selectively loads matching VT/Notus metadata, then streams enriched output.
- Preserve the enriched JSON structure introduced by issues #22 and #31, including merged Notus advisory/product behavior and CVE metadata expansion.
- Teach the Python enrichment path to call the Rust CLI as a subprocess while keeping the public Python CLI/e2e UX stable.
- Update e2e/tests so the existing workflow uses the Rust implementation under the hood.
- Add benchmarks or at least repeatable large-input validation covering memory-aware behavior.

## Impact

- Improves scalability for large scan-result sets.
- Keeps repository docs, tests, and e2e behavior aligned with the shipped output format.
- Introduces a Rust toolchain/build artifact requirement for enrichment execution in development and CI/container contexts.
- Defers embedded persistent caching until streaming/selective lookup is proven insufficient.
