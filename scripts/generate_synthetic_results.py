from __future__ import annotations

import argparse
import json
from pathlib import Path

DEFAULT_OUTPUT = Path("generated/synthetic-scan-results-500k.json")
DEFAULT_VT_METADATA_OUTPUT = Path("generated/synthetic-vt-metadata.json")
DEFAULT_RESULT_COUNT = 500_000
DEFAULT_IP_COUNT = 1_000

TEMPLATES = [
    {
        "type": "alarm",
        "oid": "1.3.6.1.4.1.25623.1.0.147696",
        "port": 0,
        "protocol": "tcp",
        "message": "Installed version: 9.53.3\nFixed version: 9.55\nInstallation path / port: /usr/bin/gs",
        "vt_metadata": {
            "oid": "1.3.6.1.4.1.25623.1.0.147696",
            "name": "Ghostscript 9.50 < 9.55.0 Sandbox Escape Vulnerability - Linux",
            "filename": "2022/artifex/gb_ghostscript_sandbox_escape_vuln_sep21_lin.nasl",
            "family": "General",
            "category": "gather_info",
            "references": [{"class": "cve", "id": "CVE-2021-3781"}],
            "tag": {
                "summary": "Ghostscript is prone to a sandbox escape vulnerability.",
                "solution": "Update to version 9.55 or later.",
                "severity_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
            },
        },
    },
    {
        "type": "alarm",
        "oid": "1.3.6.1.4.1.25623.1.0.50282",
        "port": 80,
        "protocol": "tcp",
        "message": "The remote web server exposes a synthetic HTTP service banner useful for enrichment throughput tests.",
        "vt_metadata": {
            "oid": "1.3.6.1.4.1.25623.1.0.50282",
            "name": "Synthetic HTTP Banner Exposure",
            "filename": "synthetic/http_banner_exposure.nasl",
            "family": "Web application abuses",
            "category": "attack",
            "references": [{"class": "cve", "id": "CVE-2026-050282"}],
            "tag": {"summary": "Synthetic web exposure used for enrichment load tests."},
        },
    },
    {
        "type": "alarm",
        "oid": "1.3.6.1.4.1.25623.1.0.10662",
        "port": 22,
        "protocol": "tcp",
        "message": "The remote service accepted a synthetic SSH login probe during offline test generation.",
        "vt_metadata": {
            "oid": "1.3.6.1.4.1.25623.1.0.10662",
            "name": "Synthetic SSH Authentication Probe",
            "filename": "synthetic/ssh_auth_probe.nasl",
            "family": "General",
            "category": "gather_info",
            "references": [{"class": "cve", "id": "CVE-2026-010662"}],
            "tag": {"summary": "Synthetic SSH probe used for enrichment scale testing."},
        },
    },
    {
        "type": "alarm",
        "oid": "1.3.6.1.4.1.25623.1.0.10330",
        "port": 445,
        "protocol": "tcp",
        "message": "The remote SMB endpoint returned a synthetic fingerprint for enrichment load testing.",
        "vt_metadata": {
            "oid": "1.3.6.1.4.1.25623.1.0.10330",
            "name": "Synthetic SMB Fingerprint",
            "filename": "synthetic/smb_fingerprint.nasl",
            "family": "Windows",
            "category": "gather_info",
            "references": [{"class": "cve", "id": "CVE-2026-010330"}],
            "tag": {"summary": "Synthetic SMB result for offline enrichment throughput tests."},
        },
    },
    {
        "type": "log",
        "oid": "1.3.6.1.4.1.25623.1.0.117628",
        "port": 21,
        "protocol": "tcp",
        "message": "FTP is enabled on the remote SSH service.",
        "vt_metadata": {
            "oid": "1.3.6.1.4.1.25623.1.0.117628",
            "name": "Synthetic FTP-on-SSH Detection",
            "filename": "synthetic/ftp_on_ssh_detection.nasl",
            "family": "General",
            "category": "gather_info",
            "references": [{"class": "cve", "id": "CVE-2026-117628"}],
            "tag": {"summary": "Synthetic informational result used to vary enrichment output."},
        },
    },
]


def ip_for(index: int) -> str:
    block = index // 250
    host = index % 250 + 1
    return f"10.42.{block}.{host}"


def build_result(result_id: int, host_index: int, per_host_index: int) -> dict[str, object]:
    template = TEMPLATES[(host_index * 7 + per_host_index) % len(TEMPLATES)]
    ip_address = ip_for(host_index)
    hostname = f"synthetic-host-{host_index + 1:04d}.lab"
    return {
        "id": result_id,
        "type": template["type"],
        "ip_address": ip_address,
        "hostname": hostname,
        "oid": template["oid"],
        "port": template["port"],
        "protocol": template["protocol"],
        "message": (
            f"{template['message']}\n"
            f"Synthetic target: {hostname} ({ip_address})\n"
            f"Synthetic result slot: {per_host_index + 1}"
        ),
    }


def generate_payload(*, result_count: int, ip_count: int) -> dict[str, object]:
    if result_count <= 0:
        raise ValueError("result_count must be greater than 0")
    if ip_count <= 0:
        raise ValueError("ip_count must be greater than 0")
    if result_count % ip_count != 0:
        raise ValueError("result_count must be evenly divisible by ip_count")

    results_per_ip = result_count // ip_count
    results: list[dict[str, object]] = []
    result_id = 1
    for host_index in range(ip_count):
        for per_host_index in range(results_per_ip):
            results.append(build_result(result_id, host_index, per_host_index))
            result_id += 1
    return {
        "scan_id": "synthetic-enrichment-load-test",
        "generated_by": "scripts/generate_synthetic_results.py",
        "result_count": result_count,
        "ip_count": ip_count,
        "results_per_ip": results_per_ip,
        "results": results,
    }


def generate_vt_metadata() -> list[dict[str, object]]:
    return [template["vt_metadata"] for template in TEMPLATES]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic synthetic OpenVAS-style results and VT metadata"
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--vt-metadata-output",
        type=Path,
        default=DEFAULT_VT_METADATA_OUTPUT,
        help="Write a matching synthetic vt-metadata JSON file",
    )
    parser.add_argument("--result-count", type=int, default=DEFAULT_RESULT_COUNT)
    parser.add_argument("--ip-count", type=int, default=DEFAULT_IP_COUNT)
    args = parser.parse_args()

    payload = generate_payload(result_count=args.result_count, ip_count=args.ip_count)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload), encoding="utf-8")

    vt_metadata = generate_vt_metadata()
    args.vt_metadata_output.parent.mkdir(parents=True, exist_ok=True)
    args.vt_metadata_output.write_text(json.dumps(vt_metadata), encoding="utf-8")

    print(
        f"wrote {args.result_count} results across {args.ip_count} IPs to {args.output}\n"
        f"wrote {len(vt_metadata)} VT metadata entries to {args.vt_metadata_output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
