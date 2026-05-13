# scan-examples

Example code for using the OpenVAS scanner container REST API with the Greenbone community containers.

## License

MIT. See `LICENSE`.

## What is in this repo?

- Python CLI example for the OpenVAS scanner REST API
- `scannerctl` based conversion of feed scan configs into scan JSON, plus direct custom scan JSON payloads
- Docker image for the example CLI
- Docker Compose environment with:
  - Greenbone community feed containers
  - `openvasd` REST API plus the required `ospd-openvas` scanner service/socket wiring
  - a `kirscht/metasploitable3-ub1404` target container for end-to-end scans
- Unit tests and a self-hosted GitHub Actions workflow for end-to-end validation

## Configuration

This example targets the **Greenbone community container** deployment shown in `docker-compose.yml`.

- Scanner API endpoint inside Compose: `http://openvasd:80`
- Scanner API endpoint from the host: `http://localhost:3000`
- Community feed mounts expected by the example:
  - data objects: `/feed/data-objects`
  - vulnerability tests: `/feed/vulnerability-tests`
- Certificates:
  - the bundled Compose environment uses plain HTTP internally, so no client certificate files are required for the example workflow
  - if you point the CLI at an HTTPS scanner endpoint, trust the server certificate in your runtime or use `--insecure` only for throwaway lab testing

Supported environment variables:

- `SCANNER_API_URL` — scanner REST API base URL
- `SCANNER_API_TIMEOUT` — HTTP timeout in seconds
- `DATA_OBJECTS_PATH` — mounted community `data-objects` feed path
- `VT_PATH` — mounted community `vulnerability-tests` feed path (used for both NASL content and `vt-metadata.json` enrichment lookups)
- `SCAP_PATH` — optional path to SCAP/NVD CVE JSON data for second-stage CVE enrichment after VT OID matching
- `SCANNERCTL_BIN` — path to `scannerctl`
- `SCAN_CONFIG` — scan config to convert with `scannerctl` (defaults to `full-and-fast`)
- `SCAN_CONFIG_JSON` — path to a custom scanner API scan config JSON payload, or a `.zip` containing one JSON file; when set, the e2e flow skips `scannerctl` conversion and uses this payload as a template
- `TARGET_TCP_PORTS` — optional comma-separated TCP ports for the target definition; omit it to use the scan config defaults
- `TARGET_SSH_USERNAME` / `TARGET_SSH_PASSWORD` / `TARGET_SSH_PORT` — SSH credentials to include in the scan target definition (defaults: `msfadmin` / `msfadmin` / `22` for the bundled target)
- `WAIT_BEFORE_RESULTS` — initial delay before polling for scan results in the `e2e` flow
- `RESULTS_TIMEOUT` / `RESULTS_POLL_INTERVAL` — controls for waiting until findings appear
- `CREATE_SCAN_RETRIES` / `CREATE_SCAN_RETRY_DELAY` — API warm-up retry controls for scan creation

## CLI commands

The Docker image and local package expose `openvas-example`.

### Convert a scan configuration

```bash
openvas-example convert-config \
  --host target \
  --scan-config full-and-fast \
  --data-objects-path /feed/data-objects \
  --vt-path /feed/vulnerability-tests \
  --output scan.json
```

### Scan lifecycle commands

```bash
openvas-example create-scan scan.json
openvas-example start-scan <scan-id>
openvas-example stop-scan <scan-id>
openvas-example get-results <scan-id>
openvas-example delete-scan <scan-id>
```

### Run the end-to-end flow

```bash
openvas-example e2e --host target
```

This command:
1. Resolves the mounted feed layout and either converts the requested scan config with `scannerctl` or loads a custom scan config JSON payload
2. Retries scan creation while `openvasd` is still warming up
3. Starts the scan
4. Polls according to the configured completion mode: quick checks stop after first findings; full checks wait for the scan status to reach `succeeded`
5. Fetches results in JSON format
6. Enriches each result with matching VT metadata from `vt-metadata.json` when available
7. Stops the scan after first findings in quick mode, or lets it finish naturally in full mode
8. Deletes the scan

While it runs, the CLI now emits step-by-step progress logs to stderr (handy in CI), pretty-prints the enriched findings in the log, and writes final JSON that includes the final scan status, raw `results`, `enriched_results`, and a `findings_summary` block with grouped counts by severity and type. Each `enriched_results` entry keeps the original scanner result fields at the top level and adds enrichment fields such as `vt-metadata`, `vt-metadata-status`, `cve-ids`, `cve-metadata`, and `cve-metadata-status`.

The bundled target is `kirscht/metasploitable3-ub1404` with FTP, SSH, HTTP, SMB, and MySQL enabled. Compose explicitly sets the target password to `msfadmin`, and the e2e flow includes the matching SSH credential (`msfadmin` / `msfadmin` on port `22`) in the scan target so authenticated SSH checks can run. By default, scannerctl-based conversion tries to use the scan config's default ports. If the feed does not include the referenced default port-list XML, the example falls back to the bundled metasploitable service ports `21,22,80,139,445,3306` so local runs and CI stay stable. If you want a custom target port set, pass `--tcp-ports` (or set `TARGET_TCP_PORTS`); scannerctl conversion will generate an override port list, and custom JSON payloads will have their target ports replaced.

For custom scan configs, pass `--scan-config-json` or set `SCAN_CONFIG_JSON`. The payload is treated as a template: the e2e flow replaces `target.hosts`, injects SSH credentials when configured, and preserves the payload's own ports unless `--tcp-ports` is provided. The repository includes `scanconfigs/scanconfig-modified.json.zip` from issue #17, and CI uses it as the default e2e scan config.

The e2e completion behavior is controlled by `--completion-mode` / `E2E_COMPLETION_MODE`:

- `first-results` (default): quick validation for commits and PRs; stop once initial findings are available.
- `scan-complete`: full validation for pushes to `main`; keep polling status and results until the scan finishes successfully.

For long-running CI scans, `--no-findings-increment-timeout` / `E2E_NO_FINDINGS_INCREMENT_TIMEOUT` can stop a still-running scan after the finding count has not increased for the configured number of seconds. CI sets this to 1500 seconds (25 minutes) for `main` push scans, keeping the findings collected so far and avoiding a long tail where OpenVAS keeps running without producing new results. Set it to `0` to disable the idle heuristic.

The GitHub Actions workflow can also be triggered manually. Its inputs let you choose the completion mode, results timeout, and no-findings-increment timeout. Use the `full_scan` input for a manual full scan: it forces `scan-complete` mode and disables the no-findings idle timeout so the scan waits until OpenVAS reports natural completion.

The enrichment step first uses `vt-metadata.json` from the mounted vulnerability-test feed. The code checks both `<VT_PATH>/vt-metadata.json` and `<VT_PATH>/nasl/vt-metadata.json`. If the file is unavailable, malformed, or shaped unexpectedly, the workflow still returns raw results and marks VT enrichment as unavailable on each enriched result entry instead of faceplanting.

If `--scap-path` / `SCAP_PATH` points at SCAP/NVD CVE JSON data, enrichment then uses CVE references found in the matched VT metadata to attach CVE details such as descriptions, publication timestamps, references, CWE weaknesses, CVSS metrics, and affected CPEs. SCAP enrichment is optional; missing or unreadable SCAP data is logged and each enriched result entry marks CVE metadata as unavailable rather than failing the scan workflow.

One gotcha we hit: `openvasd` does not actually run scans by itself in this community-container setup. The Compose stack also needs `ospd-openvas` plus the shared scanner socket volume, otherwise scans get created and then stall with the very helpful classic of “OSPD socket ... does not exist.”

## Compose-based test environment

Start the scanner stack and target:

```bash
docker compose up -d vulnerability-tests notus-data data-objects gpg-data redis-server configure-openvas ospd-openvas openvasd target
```

Run the example container against that stack:

```bash
docker compose run --rm example e2e --host target
```

Use a different scannerctl scan config, custom scan JSON, or explicit ports if you want to override the defaults:

```bash
docker compose run --rm \
  -e SCAN_CONFIG=full-and-fast \
  -e TARGET_TCP_PORTS=21,22,80,139,445,3306 \
  -e TARGET_SSH_USERNAME=msfadmin \
  -e TARGET_SSH_PASSWORD=msfadmin \
  example e2e --host target

docker compose run --rm \
  -e SCAN_CONFIG_JSON=/app/scanconfigs/scanconfig-modified.json.zip \
  example e2e --host target
```

## Local development with uv

Create the project environment and install dev dependencies:

```bash
uv sync --locked --extra dev
```

Run the tests or CLI inside the managed environment:

```bash
uv run pytest
uv run openvas-example --help
```

This keeps the project virtualenv in `.venv/` and avoids ad-hoc `pip install` drift.

## GitHub Actions

The repo includes `.github/workflows/tests.yml` with:
- `unit` on `ubuntu-latest`
- `e2e` on the self-hosted runner label `scan-examples-e2e`

That runner is intended to map to the dedicated Hetzner runner named `hetzner-vps-scan-examples`.

The self-hosted e2e workflow intentionally keeps the named feed volumes (`vt_data_vol`, `notus_data_vol`, `data_objects_vol`, `gpg_data_vol`) between runs so Greenbone community feed data does not need to be re-fetched every time. Transient scanner state volumes are removed during teardown.

## Reference docs

- `scan-docs.md`
- Greenbone scanner API: <https://greenbone.github.io/scanner-api/>
- Greenbone community container docs: <https://greenbone.github.io/docs/latest/22.4/container/>
