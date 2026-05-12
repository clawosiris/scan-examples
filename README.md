# scan-examples

Example code for using the OpenVAS scanner container REST API with the Greenbone community containers.

## License

MIT. See `LICENSE`.

## What is in this repo?

- Python CLI example for the OpenVAS scanner REST API
- `scannerctl` based conversion of the community feed's **Full & Fast** scan config into scan JSON
- Docker image for the example CLI
- Docker Compose environment with:
  - Greenbone community feed containers
  - `openvasd` REST API
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
- `VT_PATH` — mounted community `vulnerability-tests` feed path
- `SCANNERCTL_BIN` — path to `scannerctl`
- `TARGET_TCP_PORTS` — default comma-separated TCP ports for the target definition (defaults to `21,22,80,139,445,3306` for the bundled metasploitable target)
- `WAIT_BEFORE_RESULTS` — delay between start and stop/results in the `e2e` flow
- `CREATE_SCAN_RETRIES` / `CREATE_SCAN_RETRY_DELAY` — API warm-up retry controls for scan creation

## CLI commands

The Docker image and local package expose `openvas-example`.

### Convert the Full & Fast configuration

```bash
openvas-example convert-config \
  --host target \
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
openvas-example e2e --host target --tcp-ports 21,22,80,139,445,3306
```

This command:
1. Resolves the mounted feed layout and converts the feed's **Full & Fast** scan config with `scannerctl`
2. Retries scan creation while `openvasd` is still warming up
3. Starts the scan
4. Stops the scan after a short wait
5. Fetches results in JSON format
6. Deletes the scan

While it runs, the CLI now emits step-by-step progress logs to stderr (handy in CI), and the final result JSON includes a `findings_summary` block with the total number of findings plus grouped counts by severity and type.

The bundled target is `kirscht/metasploitable3-ub1404` with FTP, SSH, HTTP, SMB, and MySQL enabled. The default scanned TCP port set is `21,22,80,139,445,3306`, which gives the example a realistic multi-service target without turning the test into an all-day hostage situation.

## Compose-based test environment

Start the scanner stack and target:

```bash
docker compose up -d vulnerability-tests notus-data data-objects gpg-data redis-server configure-openvas openvasd target
```

Run the example container against that stack:

```bash
docker compose run --rm example e2e --host target --tcp-ports 21,22,80,139,445,3306
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
