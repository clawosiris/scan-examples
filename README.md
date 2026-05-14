# scan-examples

Example code for using the OpenVAS scanner container REST API with Greenbone community scanner
containers and feed data synchronized by `greenbone-feed-sync`.

## License

MIT. See `LICENSE`.

## What is in this repo?

- Python CLI example for the OpenVAS scanner REST API
- `scannerctl` based conversion of feed scan configs into scan JSON, plus direct custom scan JSON payloads
- Docker image for the example CLI
- Docker Compose environment with:
  - `greenbone-feed-sync` for retrieving NASL, Notus, and data-object feeds into persistent named
    volumes
  - `openvasd` REST API plus the required `ospd-openvas` scanner service/socket wiring
  - a `kirscht/metasploitable3-ub1404` target container for end-to-end scans
- Unit tests and a self-hosted GitHub Actions workflow for end-to-end validation

## Configuration

This example targets the **Greenbone community scanner container** deployment shown in
`docker-compose.yml`, with feed data retrieved by the `greenbone-feed-sync` container instead of the
community feed data-copy containers.

- Scanner API endpoint inside Compose: `http://openvasd:80`
- Scanner API endpoint from the host: `http://localhost:3000`
- Feed mounts expected by the example:
  - data objects synchronized by `greenbone-feed-sync --type gvmd-data`: `/feed/data-objects`
  - NASL vulnerability tests synchronized by `greenbone-feed-sync --type nasl`:
    `/feed/vulnerability-tests`
  - Notus advisories synchronized by `greenbone-feed-sync --type notus`:
    `/var/lib/notus/advisories`
- Certificates:
  - the bundled Compose environment uses plain HTTP internally, so no client certificate files are required for the example workflow
  - if you point the CLI at an HTTPS scanner endpoint, trust the server certificate in your runtime or use `--insecure` only for throwaway lab testing

Supported environment variables:

- `SCANNER_API_URL` — scanner REST API base URL
- `SCANNER_API_TIMEOUT` — HTTP timeout in seconds
- `DATA_OBJECTS_PATH` — mounted Greenbone data-objects feed path
- `VT_PATH` — mounted Greenbone vulnerability-tests feed path (used for NASL content and
  `vt-metadata.json` enrichment lookups)
- `NOTUS_PATH` — optional path to the mounted Notus advisory feed (`.notus` files) used for
  Notus-specific result enrichment
- `SCAP_PATH` — optional path to SCAP/NVD CVE JSON data for second-stage CVE enrichment after VT OID matching
- `SCANNERCTL_BIN` — path to `scannerctl`
- `SCAN_CONFIG` — scan config to convert with `scannerctl` (defaults to `full-and-fast`)
- `SCAN_CONFIG_JSON` — path to a custom scanner API scan config JSON payload, or a `.zip` containing one JSON file; when set, the e2e flow skips `scannerctl` conversion and uses this payload as a template
- `TARGET_TCP_PORTS` — optional comma-separated TCP ports for the target definition; omit it to use the scan config defaults
- `TARGET_SSH_USERNAME` / `TARGET_SSH_PASSWORD` / `TARGET_SSH_PORT` — SSH credentials to include in the scan target definition (defaults: `msfadmin` / `msfadmin` / `22` for the bundled target)
- `WAIT_BEFORE_RESULTS` — initial delay before polling for scan results in the `e2e` flow
- `RESULTS_TIMEOUT` / `RESULTS_POLL_INTERVAL` — controls for waiting until findings appear
- `E2E_MIN_RESULTS` — minimum result count for `first-results` mode; CI uses `1000`
- `CREATE_SCAN_RETRIES` / `CREATE_SCAN_RETRY_DELAY` — API warm-up retry controls for scan creation

## CLI commands

The Docker image and local package expose `openvas-example` for scanner lifecycle examples and
`openvas-enrich-results` for standalone result enrichment.

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

### Enrich scanner results offline

Use `openvas-enrich-results` when you already have scanner output and local feed metadata. This is
the same enrichment logic used by the e2e flow, exposed as a standalone command for post-processing
saved scanner output.

Required inputs:
- `--results` — scanner results JSON, either a raw result array or an object containing a `results`
  array
- at least one feed metadata source:
  - `--vt-metadata` — path to `vt-metadata.json` or a directory containing it
  - `--notus-path` — path to a Notus advisory file or directory containing `.notus` files

Optional inputs:
- `--scap-path` — Greenbone/NVD SCAP CVE JSON data for second-stage CVE enrichment
- `--output` — output file; omit it to print enriched JSON to stdout

```bash
openvas-enrich-results \
  --results scan-results.json \
  --vt-metadata /feed/vulnerability-tests/vt-metadata.json \
  --notus-path /var/lib/notus/advisories \
  --scap-path /feed/scap-data \
  --output enriched-results.json
```

The Python API is available from `scan_examples.enrichment` for callers that want to embed the
same logic directly:

```python
from scan_examples.enrichment import enrich_results_from_files

enriched = enrich_results_from_files(
    results_path="scan-results.json",
    vt_metadata_path="/feed/vulnerability-tests/vt-metadata.json",
    notus_path="/var/lib/notus/advisories",
    scap_path="/feed/scap-data",
)
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
6. Enriches each result with matching NASL VT metadata from `vt-metadata.json` and/or matching Notus advisory metadata from `.notus` files when available
7. Stops the scan after first findings in quick mode, or lets it finish naturally in full mode
8. Deletes the scan

While it runs, the CLI now emits step-by-step progress logs to stderr (handy in CI),
pretty-prints the enriched findings in the log, and writes final JSON that includes
the final scan status, raw `results`, `enriched_results`, and a `findings_summary`
block with grouped counts by severity and type.

Each `enriched_results` entry keeps the original scanner result fields at the top
level and adds enrichment fields such as `feed-metadata-source`, `vt-metadata`,
`vt-metadata-status`, `notus-metadata`, `notus-metadata-status`, `cve-ids`,
`cve-metadata`, and `cve-metadata-status`.

Example raw result entry:

```json
[
  {
    "id": 3,
    "type": "alarm",
    "ip_address": "127.0.0.1",
    "hostname": "localhost",
    "oid": "1.3.6.1.4.1.25623.1.0.147696",
    "protocol": "tcp",
    "message": "Installed version: 9.53.3\nFixed version: 9.55\nInstallation\npath / port: /usr/bin/gs"
  }
]
```

Example entry enriched with VT metadata only:

```json
[
  {
    "id": 3,
    "type": "alarm",
    "ip_address": "127.0.0.1",
    "hostname": "localhost",
    "oid": "1.3.6.1.4.1.25623.1.0.147696",
    "protocol": "tcp",
    "message": "Installed version: 9.53.3\nFixed version:     9.55\nInstallation\npath / port:       /usr/bin/gs",
    "vt-metadata": {
      "oid": "1.3.6.1.4.1.25623.1.0.147696",
      "name": "Ghostscript 9.50 < 9.55.0 Sandbox Escape Vulnerability - Linux",
      "filename": "2022/artifex/gb_ghostscript_sandbox_escape_vuln_sep21_lin.nasl",
      "tag": {
        "affected": "Ghostscript version 9.50 through 9.54.x.",
        "creation_date": 1645676695,
        "cvss_base_vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
        "insight": "The file access protection built into Ghostscript proved\n  insufficient for the '%pipe%' PostScript device, when combined with Ghostscript's requirement to\n  be able to create and control temporary files in the conventional temporary file directories (for\n  example, '/tmp' or '/temp').",
        "last_modification": 1646190255,
        "qod_type": "executable_version_unreliable",
        "severity_date": 1646077920,
        "severity_origin": "NVD",
        "severity_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "solution": "Update to version 9.55 or later.",
        "solution_type": "VendorFix",
        "summary": "Ghostscript is prone to a sandbox escape vulnerability.",
        "vuldetect": "Checks if a vulnerable version is present on the target host."
      },
      "dependencies": [
        "secpod_ghostscript_detect_lin.nasl"
      ],
      "required_keys": [],
      "mandatory_keys": [
        "artifex/ghostscript/lin/detected"
      ],
      "excluded_keys": [],
      "required_ports": [],
      "required_udp_ports": [],
      "references": [
        {
          "class": "cve",
          "id": "CVE-2021-3781"
        },
        {
          "class": "URL",
          "id": "https://ghostscript.com/blog/CVE-2021-3781.html"
        }
      ],
      "preferences": [],
      "category": "gather_info",
      "family": "General"
    }
  }
]
```

The bundled target is `kirscht/metasploitable3-ub1404` with FTP, SSH, HTTP, SMB, and MySQL enabled. Compose explicitly sets the target password to `msfadmin`, and the e2e flow includes the matching SSH credential (`msfadmin` / `msfadmin` on port `22`) in the scan target so authenticated SSH checks can run. By default, scannerctl-based conversion tries to use the scan config's default ports. If the feed does not include the referenced default port-list XML, the example falls back to the bundled metasploitable service ports `21,22,80,139,445,3306` so local runs and CI stay stable. If you want a custom target port set, pass `--tcp-ports` (or set `TARGET_TCP_PORTS`); scannerctl conversion will generate an override port list, and custom JSON payloads will have their target ports replaced.

For custom scan configs, pass `--scan-config-json` or set `SCAN_CONFIG_JSON`. The payload is treated as a template: the e2e flow replaces `target.hosts`, injects SSH credentials when configured, and preserves the payload's own ports unless `--tcp-ports` is provided. The repository includes `scanconfigs/scanconfig-modified.json.zip` from issue #17, and CI uses it as the default e2e scan config.

The e2e completion behavior is controlled by `--completion-mode` / `E2E_COMPLETION_MODE`:

- `first-results` (default): quick validation for commits and PRs; stop once the configured minimum
  number of findings is available. Use `--min-results` / `E2E_MIN_RESULTS` to raise that threshold;
  CI waits for the first 1000 results.
- `scan-complete`: full validation for pushes to `main`; keep polling status and results until the scan finishes successfully.

For long-running CI scans, `--no-findings-increment-timeout` / `E2E_NO_FINDINGS_INCREMENT_TIMEOUT` can stop a still-running scan after the finding count has not increased for the configured number of seconds. CI sets this to 1500 seconds (25 minutes) for `main` push scans, keeping the findings collected so far and avoiding a long tail where OpenVAS keeps running without producing new results. Set it to `0` to disable the idle heuristic.

The GitHub Actions workflow can also be triggered manually. Its inputs let you choose the
completion mode, results timeout, and no-findings-increment timeout.

To run a full scan manually from GitHub Actions:

1. Open the repository's **Actions** tab.
2. Select the **tests** workflow.
3. Click **Run workflow**.
4. Choose the branch to run, usually `main`.
5. Set `full_scan` to `true`.
6. Optionally raise `results_timeout` if you expect the scan to take longer than the default
   1800 seconds.
7. Click **Run workflow**.

When `full_scan` is `true`, the workflow forces `scan-complete` mode and sets the no-findings
idle timeout to `0`, so the scan waits until OpenVAS reports natural completion. The workflow
uploads `scan-results.json` and `docker-compose.log` as the `scan-examples-e2e-artifacts` artifact.

The enrichment step first uses `vt-metadata.json` from the mounted NASL vulnerability-test feed.
The code checks both `<VT_PATH>/vt-metadata.json` and `<VT_PATH>/nasl/vt-metadata.json`.
If the file is unavailable, malformed, or shaped unexpectedly, the workflow still returns raw
results and marks VT enrichment as unavailable on each enriched result entry instead of
faceplanting.

For Notus-backed results, the example can also index the mounted `.notus` advisory files from
`<NOTUS_PATH>` (for example `/var/lib/notus/advisories`). Those files provide OID-keyed product
and fixed-package metadata for Notus advisories, which is separate from `vt-metadata.json`.

If `--scap-path` / `SCAP_PATH` points at SCAP/NVD CVE JSON data, enrichment then uses
CVE references found in the matched VT metadata to attach CVE details such as descriptions,
publication timestamps, references, CWE weaknesses, CVSS metrics, and affected CPEs.
SCAP enrichment is optional; missing or unreadable SCAP data is logged and each enriched result
entry marks CVE metadata as unavailable rather than failing the scan workflow.

One gotcha we hit: `openvasd` does not actually run scans by itself in this community-container setup. The Compose stack also needs `ospd-openvas` plus the shared scanner socket volume, otherwise scans get created and then stall with the very helpful classic of “OSPD socket ... does not exist.”

## Compose-based test environment

Synchronize the Greenbone feed into persistent named volumes, then start the scanner stack and target:

```bash
docker compose up greenbone-feed-sync
docker compose up -d gpg-data redis-server configure-openvas ospd-openvas openvasd target
```

The `greenbone-feed-sync` service downloads NASL VTs, Notus data, and GVMD data objects
(`scan-configs`, `port-lists`, etc.) using rsync. The named volumes (`vt_data_vol`,
`notus_data_vol`, and `data_objects_vol`) are reused by later runs, so subsequent synchronizations
only fetch deltas instead of starting from empty feed containers.

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

The self-hosted e2e workflow runs `greenbone-feed-sync` before starting the scanner stack and
intentionally keeps the named feed volumes (`vt_data_vol`, `notus_data_vol`, `data_objects_vol`,
`gpg_data_vol`) between runs so Greenbone feed data is updated incrementally instead of re-fetched
from scratch every time. Transient scanner state volumes are removed during teardown.

## Reference docs

- `scan-docs.md`
- Greenbone scanner API: <https://greenbone.github.io/scanner-api/>
- Greenbone community container docs: <https://greenbone.github.io/docs/latest/22.4/container/>
