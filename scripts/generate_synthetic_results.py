from __future__ import annotations

import argparse
import json
from pathlib import Path

DEFAULT_OUTPUT = Path("generated/synthetic-scan-results-500k.json")
DEFAULT_RESULT_COUNT = 500_000
DEFAULT_IP_COUNT = 1_000

TEMPLATES = [
    {
        "type": "alarm",
        "oid": "1.3.6.1.4.1.25623.1.0.147696",
        "port": 0,
        "protocol": "tcp",
        "message": "Installed version: 9.53.3\\nFixed version: 9.55\\nInstallation path / port: /usr/bin/gs",
    },
    {
        "type": "alarm",
        "oid": "1.3.6.1.4.1.25623.1.0.50282",
        "port": 80,
        "protocol": "tcp",
        "message": "The remote web server exposes a synthetic HTTP service banner useful for enrichment throughput tests.",
    },
    {
        "type": "alarm",
        "oid": "1.3.6.1.4.1.25623.1.0.10662",
        "port": 22,
        "protocol": "tcp",
        "message": "The remote service accepted a synthetic SSH login probe during offline test generation.",
    },
    {
        "type": "alarm",
        "oid": "1.3.6.1.4.1.25623.1.0.10330",
        "port": 445,
        "protocol": "tcp",
        "message": "The remote SMB endpoint returned a synthetic fingerprint for enrichment load testing.",
    },
    {
        "type": "log",
        "oid": "1.3.6.1.4.1.25623.1.0.117628",
        "port": 21,
        "protocol": "tcp",
        "message": "FTP is enabled on the remote SSH service.",
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
    message = (
        f"{template['message']}\\n"
        f"Synthetic target: {hostname} ({ip_address})\\n"
        f"Synthetic result slot: {per_host_index + 1}"
    )
    return {
        "id": result_id,
        "type": template["type"],
        "ip_address": ip_address,
        "hostname": hostname,
        "oid": template["oid"],
        "port": template["port"],
        "protocol": template["protocol"],
        "message": message,
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic synthetic OpenVAS-style result set for enrichment testing"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output JSON path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--result-count",
        type=int,
        default=DEFAULT_RESULT_COUNT,
        help=f"Total number of results to generate (default: {DEFAULT_RESULT_COUNT})",
    )
    parser.add_argument(
        "--ip-count",
        type=int,
        default=DEFAULT_IP_COUNT,
        help=f"Distinct IP count to spread results across (default: {DEFAULT_IP_COUNT})",
    )
    args = parser.parse_args()

    payload = generate_payload(result_count=args.result_count, ip_count=args.ip_count)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload), encoding="utf-8")
    print(
        f"wrote {args.result_count} results across {args.ip_count} IPs to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
