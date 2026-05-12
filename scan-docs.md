# DETECT Workflow and API Documentation

This document describes the end-to-end workflow for configuring, running, and enriching vulnerability scans using the Greenbone scanner API and DETECT container/feed setup.

## Table of Contents

- [Overview](#overview)
- [Scanning Workflow](#scanning-workflow)
  - [Scan Configuration Conversion](#scan-configuration-conversion)
  - [1. Create a Scan](#1-create-a-scan)
  - [2. Start or Stop a Scan](#2-start-or-stop-a-scan)
  - [3. Get Scan Results](#3-get-scan-results)
  - [4. Delete a Scan](#4-delete-a-scan)
- [Data Enrichment](#data-enrichment)
  - [VT Metadata](#vt-metadata)
  - [SCAP Data](#scap-data)
- [Feed Structure](#feed-structure)
  - [Necessary Data for DETECT and Data Enrichment](#necessary-data-for-detect-and-data-enrichment)
  - [Feed Synchronization](#feed-synchronization)
- [DETECT Container Configuration](#detect-container-configuration)
  - [Configuration Variables](#configuration-variables)
  - [Docker Compose Examples](#docker-compose-examples)
- [References](#references)

## Overview

To carry out an effective scan, the scan must be configured with:

1. A **scan configuration**, which determines the scope of the scan.
2. Scan **parameters**, which define the scan characteristics.

The workflow is based on the Greenbone scanner API and OpenVAS DETECT documentation.

## Scanning Workflow

For a simple scan, use the **Full & Fast** scan configuration. This configuration is included in the feed as an XML file and can be converted for DETECT usage.

### Scan Configuration Conversion

Relevant upstream references:

- [Greenbone scanner API](https://greenbone.github.io/scanner-api/#/)
- [OpenVAS DETECT documentation](https://docs.greenbone.net/OPENVAS/OPENVAS-DETECT-documentation-EN.pdf)
- [Scannerctl scan-config documentation](https://github.com/greenbone/openvas-scanner/tree/main/rust/src/scannerctl#scan-config)
- [Example scan configs](https://github.com/greenbone/openvas-scanner/blob/f6c23625f5b1c4cf5c63ea3145f2f5b4d39e1c54/rust/examples/scannerctl/scan-configs/README.md?plain=1#L1)

### 1. Create a Scan

```http
POST /scans
```

This request creates the scan. It can be started afterwards with the scan action request.

The content of the **Full & Fast** JSON must be inserted under `vts`.

The response returns the **scan ID**, which is required for subsequent queries and to start the scan.

#### Simple Scan

```json
{
  "target": {
    "hosts": [
      "127.0.0.1"
    ],
    "ports": [
      {
        "range": [
          {
            "start": 22
          }
        ]
      }
    ],
    "credentials": [
      {
        "service": "ssh",
        "port": 22,
        "up": {
          "username": "user",
          "password": "pass"
        }
      }
    ]
  },
  "vts": [
    {
      "oid": "1.3.6.1.4.1.25623.1.0.50282"
    }
  ]
}
```

#### Complex Scan

Scanner preferences reference:

- [OpenVAS scanner manual](https://github.com/greenbone/openvas-scanner/blob/main/doc/manual/openvas/openvas.md)

```json
{
  "target": {
    "hosts": [
      "127.0.0.1",
      "192.168.0.1-15",
      "10.0.5.0/24",
      "::1",
      "2001:db8:0000:0000:0000:0000:0000:0001-00ff",
      "2002::1234:abcd:ffff:c0a8:101/64",
      "examplehost"
    ],
    "excluded_hosts": [
      "192.168.0.14"
    ],
    "ports": [
      {
        "protocol": "udp",
        "range": [
          {
            "start": 22
          },
          {
            "start": 1024,
            "end": 1030
          }
        ]
      },
      {
        "protocol": "tcp",
        "range": [
          {
            "start": 24,
            "end": 30
          }
        ]
      },
      {
        "range": [
          {
            "start": 100,
            "end": 1000
          }
        ]
      }
    ],
    "credentials": [
      {
        "service": "ssh",
        "port": 22,
        "usk": {
          "username": "user",
          "password": "pw",
          "private": "ssh-key..."
        }
      },
      {
        "service": "smb",
        "up": {
          "username": "user",
          "password": "pw"
        }
      },
      {
        "service": "snmp",
        "snmp": {
          "username": "user",
          "password": "pw",
          "community": "my_community",
          "auth_algorithm": "md5",
          "privacy_password": "priv_pw",
          "privacy_algorithm": "aes"
        }
      }
    ],
    "alive_test_ports": [
      {
        "protocol": "tcp",
        "range": [
          {
            "start": 1,
            "end": 100
          }
        ]
      },
      {
        "range": [
          {
            "start": 443
          }
        ]
      }
    ],
    "alive_test_methods": [
      "icmp",
      "tcp_syn",
      "tcp_ack",
      "arp",
      "consider_alive"
    ],
    "reverse_lookup_unify": true,
    "reverse_lookup_only": false
  },
  "scan_preferences": [],
  "vts": [
    {
      "oid": "1.3.6.1.4.1.25623.1.0.10662",
      "parameters": [
        {
          "id": 1,
          "value": "200"
        },
        {
          "id": 2,
          "value": "yes"
        }
      ]
    },
    {
      "oid": "1.3.6.1.4.1.25623.1.0.10330"
    }
  ]
}
```

### 2. Start or Stop a Scan

```http
POST /scans/{id}
```

To start a scheduled scan, send the following request body:

```json
{
  "action": "start"
}
```

A scan that is already running can be stopped in the same way by using the corresponding action.

### 3. Get Scan Results

```http
GET /scans/{id}/results
```

Use the scan ID to retrieve results. Results can also be filtered by range to obtain smaller batches. This is useful because scanning a Class C network can yield thousands of results.

Result types include:

| Type | Meaning |
|---|---|
| `alarm` | Vulnerability notification |
| `error` | Error that occurred during a VT, for example a timeout |
| `host_start` | Timestamp for the start of host scanning |
| `host_stop` | Timestamp for the end of host scanning |
| `host_details` | Host metadata, such as TLS certificate information |
| `log` | Informational scanner output |

#### Example Result Response

```json
[
  {
    "id": 0,
    "type": "host_start",
    "ip_address": "127.0.0.1",
    "port": 22,
    "protocol": "tcp",
    "message": "Thu Mar 23 15:16:37 2023"
  },
  {
    "id": 1,
    "type": "error",
    "ip_address": "127.0.0.1",
    "hostname": "localhost",
    "protocol": "tcp",
    "message": "MQTT initialization failed"
  },
  {
    "id": 2,
    "type": "log",
    "ip_address": "127.0.0.1",
    "hostname": "localhost",
    "oid": "1.3.6.1.4.1.25623.1.0.117628",
    "port": 22,
    "protocol": "tcp",
    "message": "FTP is enabled on the remote SSH service."
  },
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

### 4. Delete a Scan

```http
DELETE /scans/{id}
```

Delete the scan after retrieving the required data.

## Data Enrichment

The scanner result data is intentionally minimal and must be enriched after retrieval.

### VT Metadata

VT metadata is contained in the feed and can be mapped using the OID from each scanner result. Therefore, all scanner results should be expanded using the data from `vt-metadata.json`.

For example, the scanner result above reports a vulnerability with the OID:

```text
1.3.6.1.4.1.25623.1.0.147696
```

The corresponding metadata entry in `vt-metadata.json` contains details such as the VT name, filename, severity information, solution, references, dependencies, and affected products.

#### Example VT Metadata Entry

```json
{
  "oid": "1.3.6.1.4.1.25623.1.0.147696",
  "name": "Ghostscript 9.50 < 9.55.0 Sandbox Escape Vulnerability - Linux",
  "filename": "2022/artifex/gb_ghostscript_sandbox_escape_vuln_sep21_lin.nasl",
  "tag": {
    "affected": "Ghostscript version 9.50 through 9.54.x.",
    "creation_date": 1645676695,
    "cvss_base_vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
    "insight": "The file access protection built into Ghostscript proved insufficient for the '%pipe%' PostScript device, when combined with Ghostscript's requirement to be able to create and control temporary files in the conventional temporary file directories, for example '/tmp' or '/temp'.",
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
```

### SCAP Data

VT metadata can reference other sources, such as CVE IDs. These CVE IDs can be used to enrich scan results with information from SCAP data.

For the example OID `1.3.6.1.4.1.25623.1.0.147696`, the referenced CVE is:

```text
CVE-2021-3781
```

SCAP data for this CVE includes:

- Publication and last-modified timestamps
- CVE descriptions in multiple languages
- References and vendor advisories
- Weaknesses such as CWE entries
- CPE product matching data
- CVSS v3.1 and v2 metrics

Relevant CVSS data from the example:

| Metric | Value |
|---|---|
| CVSS version | 3.1 |
| Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| Base score | `9.9` |
| Base severity | `CRITICAL` |
| Attack vector | `NETWORK` |
| Attack complexity | `LOW` |
| Privileges required | `LOW` |
| User interaction | `NONE` |
| Scope | `CHANGED` |
| Confidentiality impact | `HIGH` |
| Integrity impact | `HIGH` |
| Availability impact | `HIGH` |

## Feed Structure

### Necessary Data for DETECT and Data Enrichment

The following data must be distributed from the Greenbone feed to end-customer DETECT instances.

| Title | Content | Feed Location | Signed | Size | Purpose |
|---|---|---|---:|---:|---|
| CERT-Bund | Advisories published by CERT-Bund, the Computer Emergency Response Team for Germany's federal authorities. | `vulnerability-feed/<version>/cert-data/CB-K*.xml` | Yes | 100 MB | Data enrichment based on CVE ID |
| notus-data | Vulnerability information used by the Notus Scanner to detect vulnerabilities based on collected system information. | `vulnerability-feed/<version>/vt-data/notus/` | Yes | 800 MB | DETECT relevant for scanning |
| NASL vulnerability tests | NASL scripts run by a scan engine like `openvas-scanner`; they establish a connection to a remote target system to check for known vulnerabilities. | `vulnerability-feed/<version>/vt-data/nasl/` | Yes | 900 MB | DETECT relevant for scanning |
| SCAP | Information on products in CPE format and vulnerabilities in CVE format, published by NIST. | `vulnerability-feed/<version>/scap-data/` | No | 1.16 GB | Data enrichment based on CVE |
| data-objects | Port lists and configurations for vulnerability and policy scans. | `data-feed/<version>/configs/`, `data-feed/<version>/port-lists/`, `data-feed/<version>/scan-configs/` | No | 25 MB | Scan config for DETECT, converted to JSON |
| DFN-CERT | Advisories published by DFN-CERT for Germany's broader scientific community. | `vulnerability-feed/<version>/cert-data/dfn-cert-*.xml` | Yes | 50 MB | Data enrichment based on CVE ID |
| vt-metadata.json | Metadata for all NASL tests. | `vulnerability-feed/<version>/vt-data/nasl/vt-metadata.json` | Yes | 215 MB | Data enrichment based on OID from scanner result |

### Feed Synchronization

The feed can be synchronized using the Greenbone Feed Sync Script:

- [greenbone-feed-sync](https://github.com/greenbone/greenbone-feed-sync)

The same script can synchronize with the Greenbone Enterprise Feed using an Enterprise Feed Key:

- [Greenbone Enterprise Feed Key](https://github.com/greenbone/greenbone-feed-sync#greenbone-enterprise-feed-key)

Synchronization endpoints:

| Item | Value |
|---|---|
| Feed synchronization URL | `feed.greenbone.net` |
| Self-hosted registry | `packages.greenbone.net` |

## DETECT Container Configuration

### Configuration Variables

| Variable | Mode | Example Value | Description | Docker Compose Usage |
|---|---|---|---|---|
| `FEED_PATH` | `volume` | `volume` | Feed data stored in a Docker volume. This is the default. | `export FEED_MODE='volume'` |
| `FEED_PATH` | `mount` | `/host/path/to/feed` | Feed data mounted from a host directory. | `export FEED_MODE='mount'; export FEED_PATH='/host/path/to/feed'` |
| `FEED_SYNC_GSF_KEY` | - | From `feed.key` file | Key for feed synchronization. Required if `FEED_MODE=volume`. | `export FEED_SYNC_GSF_KEY="$(< ${CERT_DIR_DETECT}/feed.key)"` |
| `CCERT_PATH` | `env` | `env` | Client certificates passed as environment variables. | `export CCERT_MODE='env'` |
| `CCERT_PATH` | `mount` | `/host/path/to/certs` | Client certificates mounted from a host directory. | `export CCERT_MODE='mount'; export CCERT_PATH='/host/path/to/certs'` |
| `OPENVAS_SCANNER_TLS_CERT` | - | From `server.crt` | Server TLS certificate embedded as an environment variable. | `export OPENVAS_SCANNER_TLS_CERT="$(< ${CERT_DIR_DETECT}/server.crt)"` |
| `OPENVAS_SCANNER_TLS_KEY` | - | From `server.key` | Server TLS private key embedded as an environment variable. | `export OPENVAS_SCANNER_TLS_KEY="$(< ${CERT_DIR_DETECT}/server.key)"` |
| `OPENVAS_SCANNER_TLS_CLIENT_CERT` | - | From `client.crt` | Client TLS certificate embedded as an environment variable. | `export OPENVAS_SCANNER_TLS_CLIENT_CERT="$(< ${CERT_DIR_DETECT}/client.crt)"` |
| `OPENVAS_SCANNER_HOST_LISTEN_ADDR` | - | `0.0.0.0` | Host IP for the scanner to listen on. Default is `0.0.0.0`. | `export OPENVAS_SCANNER_HOST_LISTEN_ADDR="0.0.0.0"` |
| `OPENVAS_SCANNER_HOST_LISTEN_PORT` | - | `443` | Published scanner port. Default is `443`. | `export OPENVAS_SCANNER_HOST_LISTEN_PORT="443"` |
| `OPENVAS_SCANNER__CONFIG` | - | Scanner config content | Content of the OpenVAS scanner configuration file. | `export OPENVAS_SCANNER__CONFIG="$(< ${CERT_DIR_DETECT}/scanner.conf)"` |
| `OPENVAS_SCANNER_OPENVASD_MODE` | - | `notus` | Mode for OpenVAS scanner, for example `service` or `notus`. Default is `service`. | `export OPENVAS_SCANNER_OPENVASD_MODE="notus"` |

Default scanner configuration example:

```text
table_driven_lsc = yes
openvasd_server = https://0.0.0.0:8443
```

### Docker Compose Examples

#### 1. Feed on Volume Default

```bash
export FEED_MODE=volume
export FEED_SYNC_GSF_KEY="$(< ${CERT_DIR_DETECT}/feed.key)"
export OPENVAS_SCANNER_TLS_CERT="$(< ${CERT_DIR_DETECT}/server.crt)"
export OPENVAS_SCANNER_TLS_KEY="$(< ${CERT_DIR_DETECT}/server.key)"
export OPENVAS_SCANNER_TLS_CLIENT_CERT="$(< ${CERT_DIR_DETECT}/client.crt)"
export OPENVAS_SCANNER_HOST_LISTEN_ADDR="0.0.0.0"
export OPENVAS_SCANNER_HOST_LISTEN_PORT="443"

docker compose --env-file settings.env up -d
```

#### 2. Feed Mounted from Host

```bash
export FEED_MODE=mount
export FEED_PATH=/host/path/to/feed
export OPENVAS_SCANNER_TLS_CERT="$(< ${CERT_DIR_DETECT}/server.crt)"
export OPENVAS_SCANNER_TLS_KEY="$(< ${CERT_DIR_DETECT}/server.key)"
export OPENVAS_SCANNER_TLS_CLIENT_CERT="$(< ${CERT_DIR_DETECT}/client.crt)"
export OPENVAS_SCANNER_HOST_LISTEN_ADDR="0.0.0.0"
export OPENVAS_SCANNER_HOST_LISTEN_PORT="443"

docker compose --env-file settings.env up -d
```

#### 3. Client Certificates as Environment Variables

```bash
export CCERT_MODE=env
export OPENVAS_SCANNER_TLS_CERT="$(< ${CERT_DIR_DETECT}/server.crt)"
export OPENVAS_SCANNER_TLS_KEY="$(< ${CERT_DIR_DETECT}/server.key)"
export OPENVAS_SCANNER_TLS_CLIENT_CERT="$(< ${CERT_DIR_DETECT}/client.crt)"
export OPENVAS_SCANNER_HOST_LISTEN_ADDR="0.0.0.0"
export OPENVAS_SCANNER_HOST_LISTEN_PORT="443"

docker compose --env-file settings.env up -d
```

#### 4. Client Certificates Mounted from Host

```bash
export CCERT_MODE=mount
export CCERT_PATH=/host/path/to/certs
export OPENVAS_SCANNER_TLS_CERT="$(< ${CERT_DIR_DETECT}/server.crt)"
export OPENVAS_SCANNER_TLS_KEY="$(< ${CERT_DIR_DETECT}/server.key)"
export OPENVAS_SCANNER_HOST_LISTEN_ADDR="0.0.0.0"
export OPENVAS_SCANNER_HOST_LISTEN_PORT="443"

docker compose --env-file settings.env up -d
```

## References

- [Greenbone scanner API](https://greenbone.github.io/scanner-api/#/)
- [OpenVAS DETECT documentation](https://docs.greenbone.net/OPENVAS/OPENVAS-DETECT-documentation-EN.pdf)
- [Scannerctl scan-config documentation](https://github.com/greenbone/openvas-scanner/tree/main/rust/src/scannerctl#scan-config)
- [OpenVAS scanner manual](https://github.com/greenbone/openvas-scanner/blob/main/doc/manual/openvas/openvas.md)
- [Greenbone feed sync](https://github.com/greenbone/greenbone-feed-sync)
