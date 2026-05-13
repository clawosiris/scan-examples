# scan-examples

Example code for using the OpenVAS scanner container REST API with the Greenbone community containers.

## License

MIT. See `LICENSE`.

## What is in this repo?

- Python CLI example for the OpenVAS scanner REST API
- `scannerctl` based conversion of feed scan configs into scan JSON (defaults to **Full & Fast**)
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
- `SCANNERCTL_BIN` — path to `scannerctl`
- `SCAN_CONFIG` — scan config to convert (defaults to `full-and-fast`)
- `TARGET_TCP_PORTS` — optional comma-separated TCP ports for the target definition; omit it to use the scan config defaults
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
1. Resolves the mounted feed layout and converts the requested scan config with `scannerctl` (default: **Full & Fast**)
2. Retries scan creation while `openvasd` is still warming up
3. Starts the scan
4. Polls until findings appear in the results (or times out)
5. Fetches results in JSON format
6. Enriches each result with matching VT metadata from `vt-metadata.json` when available
7. Stops the scan cleanly after results are captured (or during timeout cleanup)
8. Deletes the scan

While it runs, the CLI now emits step-by-step progress logs to stderr (handy in CI), pretty-prints the enriched findings in the log, and writes final JSON that includes both raw `results` and `enriched_results` plus a `findings_summary` block with grouped counts by severity and type.

The bundled target is `kirscht/metasploitable3-ub1404` with FTP, SSH, HTTP, SMB, and MySQL enabled. By default the e2e flow tries to use the scan config's default ports. If the feed does not include the referenced default port-list XML, the example falls back to the bundled metasploitable service ports `21,22,80,139,445,3306` so local runs and CI stay stable. If you want a custom target port set, pass `--tcp-ports` (or set `TARGET_TCP_PORTS`) and the example will generate an override port list for scannerctl.

The enrichment step uses `vt-metadata.json` from the mounted vulnerability-test feed. The code checks both `<VT_PATH>/vt-metadata.json` and `<VT_PATH>/nasl/vt-metadata.json`. If the file is unavailable, malformed, or shaped unexpectedly, the workflow still returns raw results and marks enrichment as unavailable instead of faceplanting.

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

Use a different scan config or explicit ports if you want to override the defaults:

```bash
docker compose run --rm \
  -e SCAN_CONFIG=full-and-fast \
  -e TARGET_TCP_PORTS=21,22,80,139,445,3306 \
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
