## 1. Feed-based enrichment example

- [ ] 1.1 Add code that loads VT metadata from the mounted feed data and indexes it by OID.
- [ ] 1.2 Enrich scan results by attaching matched VT metadata fields to each result.
- [ ] 1.3 Define a stable enriched JSON shape that preserves the original result data while adding feed metadata.

## 2. Human-readable output

- [ ] 2.1 Pretty-print enriched findings in the e2e flow or CI log.
- [ ] 2.2 Document which feed file is used for enrichment and how the printed output relates to the JSON artifact.

## 3. Verification

- [ ] 3.1 Add unit tests for VT metadata lookup and result enrichment.
- [ ] 3.2 Add or update e2e expectations to cover enriched JSON output and readable CI logging.
