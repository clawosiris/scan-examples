## Why

Issue #5 asks for example code that enriches scanner results with metadata from the Greenbone feed instead of leaving raw findings as bare scanner output.

The repository already documents that scanner results are intentionally minimal and that `vt-metadata.json` is the primary feed source for expanding a result by OID. What is missing is runnable example code that actually performs that enrichment and exposes the result in a way that is useful in CI logs as well as downstream automation.

Without this, users have to reverse-engineer the feed lookup process themselves and CI output remains harder to interpret than it needs to be.

## What Changes

- Add example enrichment code that maps scanner results to VT metadata entries using each result OID.
- Produce a stable enriched JSON payload that keeps the original scanner result and adds selected feed metadata.
- Pretty-print enriched findings in the e2e/CI log so humans can quickly inspect what was found.
- Document the enrichment flow and the required feed input in the repository docs.
- Add tests covering feed lookup and enriched output shaping.

## Impact

- Makes the repository demonstrate not just scanning, but the first useful post-processing step users actually need.
- Improves CI observability by surfacing readable enriched findings instead of only raw scan output.
- Introduces a dependency on the mounted `vt-metadata.json` feed content for enrichment examples and tests.
