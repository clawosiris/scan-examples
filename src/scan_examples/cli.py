from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable

from .client import OpenVASScannerClient
from .conversion import convert_full_and_fast, discover_feed_layout
from .e2e import dump_result, run_lifecycle
from .feed import dump_pretty_enriched_results, enrich_results, load_vt_metadata_index


def _non_negative_float(raw: str) -> float:
    value = float(raw)
    if value < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return value


def _build_client(args: argparse.Namespace) -> OpenVASScannerClient:
    return OpenVASScannerClient(
        base_url=args.base_url,
        timeout=args.timeout,
        verify_tls=not args.insecure,
    )


def _dump_json(payload: Any, output: str | None) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


def _parse_ports(raw: str | None) -> list[int]:
    if not raw:
        return []
    return [int(part.strip()) for part in raw.split(",") if part.strip()]


def _load_vt_index_for_cli(vt_path: str, progress: Callable[[str], None] | None = None) -> dict[str, dict[str, Any]] | None:
    try:
        metadata_path, vt_index = load_vt_metadata_index(vt_path)
    except FileNotFoundError:
        if progress is not None:
            progress(f"VT metadata file not found under {vt_path}; continuing without enrichment")
        return None

    if progress is not None:
        progress(f"Loaded VT metadata index from {metadata_path}")
    return vt_index


def cmd_convert(args: argparse.Namespace) -> int:
    layout = discover_feed_layout(args.data_objects_path, args.vt_path)
    payload = convert_full_and_fast(
        layout=layout,
        hosts=args.host,
        tcp_ports=_parse_ports(args.tcp_ports),
        scannerctl_bin=args.scannerctl_bin,
    )
    _dump_json(payload, args.output)
    return 0


def cmd_create(args: argparse.Namespace) -> int:
    client = _build_client(args)
    payload = json.loads(Path(args.scan_json).read_text(encoding="utf-8"))
    scan_id = client.create_scan(payload)
    _dump_json({"scan_id": scan_id}, args.output)
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    client = _build_client(args)
    _dump_json(client.start_scan(args.scan_id), args.output)
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    client = _build_client(args)
    _dump_json(client.stop_scan(args.scan_id), args.output)
    return 0


def cmd_results(args: argparse.Namespace) -> int:
    client = _build_client(args)
    results = client.get_results(args.scan_id)
    vt_index = _load_vt_index_for_cli(args.vt_path)
    _dump_json(
        {
            "scan_id": args.scan_id,
            "results": results,
            "enriched_results": enrich_results(results, vt_index),
        },
        args.output,
    )
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    client = _build_client(args)
    response = client.delete_scan(args.scan_id)
    _dump_json({"scan_id": args.scan_id, "deleted": True, "response": response}, args.output)
    return 0


def cmd_e2e(args: argparse.Namespace) -> int:
    def progress(message: str) -> None:
        print(f"[e2e] {message}", file=sys.stderr, flush=True)

    tcp_ports = _parse_ports(args.tcp_ports)
    ports_rendered = ", ".join(str(port) for port in tcp_ports) if tcp_ports else "default port list from scanner config"
    progress(f"Target hosts: {', '.join(args.host)}")
    progress(f"Scanning TCP ports: {ports_rendered}")
    progress("Discovering Greenbone community feed layout")
    layout = discover_feed_layout(args.data_objects_path, args.vt_path)
    vt_index = _load_vt_index_for_cli(args.vt_path, progress=progress)
    progress("Converting Full & Fast configuration with scannerctl")
    payload = convert_full_and_fast(
        layout=layout,
        hosts=args.host,
        tcp_ports=tcp_ports,
        scannerctl_bin=args.scannerctl_bin,
    )
    client = _build_client(args)
    result = run_lifecycle(
        client=client,
        payload=payload,
        wait_before_results=args.wait_before_results,
        create_retries=args.create_retries,
        create_retry_delay=args.create_retry_delay,
        results_timeout=args.results_timeout,
        results_poll_interval=args.results_poll_interval,
        vt_index=vt_index,
        progress=progress,
    )
    progress(f"Findings summary: {json.dumps(result.findings_summary, sort_keys=True)}")
    progress(f"Enriched findings:\n{dump_pretty_enriched_results(result.enriched_results)}")
    rendered = dump_result(result)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        progress(f"Wrote e2e result payload to {args.output}")
    else:
        print(rendered)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OpenVAS Scanner REST API example")
    parser.set_defaults(func=None)

    def add_shared_api_flags(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--base-url",
            default=os.environ.get("SCANNER_API_URL", "http://openvasd:80"),
            help="Base URL for the OpenVAS scanner REST API",
        )
        command.add_argument(
            "--timeout",
            type=float,
            default=float(os.environ.get("SCANNER_API_TIMEOUT", "30")),
            help="HTTP request timeout in seconds",
        )
        command.add_argument(
            "--insecure",
            action="store_true",
            help="Disable TLS verification for HTTPS endpoints",
        )
        command.add_argument("--output", help="Write JSON output to a file")

    def add_vt_path_flag(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--vt-path",
            default=os.environ.get("VT_PATH", "/feed/vulnerability-tests"),
            help="Path to the Greenbone VT feed",
        )

    def add_shared_feed_flags(command: argparse.ArgumentParser, *, include_output: bool = True) -> None:
        command.add_argument(
            "--data-objects-path",
            default=os.environ.get("DATA_OBJECTS_PATH", "/feed/data-objects"),
            help="Path to the Greenbone data-objects feed",
        )
        add_vt_path_flag(command)
        command.add_argument(
            "--scannerctl-bin",
            default=os.environ.get("SCANNERCTL_BIN", "scannerctl"),
            help="Path to the scannerctl binary",
        )
        command.add_argument(
            "--host",
            action="append",
            required=True,
            help="Target host (repeat for multiple hosts)",
        )
        command.add_argument(
            "--tcp-ports",
            default=os.environ.get("TARGET_TCP_PORTS", "21,22,80,139,445,3306"),
            help="Comma-separated list of TCP ports for the example target",
        )
        if include_output:
            command.add_argument("--output", help="Write JSON output to a file")

    subparsers = parser.add_subparsers(dest="command")

    convert = subparsers.add_parser("convert-config", help="Convert Full & Fast scan config to scan JSON")
    add_shared_feed_flags(convert)
    convert.set_defaults(func=cmd_convert)

    create = subparsers.add_parser("create-scan", help="Create a scan from a JSON payload file")
    add_shared_api_flags(create)
    create.add_argument("scan_json", help="Path to a scan JSON payload file")
    create.set_defaults(func=cmd_create)

    start = subparsers.add_parser("start-scan", help="Start a scan")
    add_shared_api_flags(start)
    start.add_argument("scan_id")
    start.set_defaults(func=cmd_start)

    stop = subparsers.add_parser("stop-scan", help="Stop a scan")
    add_shared_api_flags(stop)
    stop.add_argument("scan_id")
    stop.set_defaults(func=cmd_stop)

    results = subparsers.add_parser("get-results", help="Fetch scan results")
    add_shared_api_flags(results)
    add_vt_path_flag(results)
    results.add_argument("scan_id")
    results.set_defaults(func=cmd_results)

    delete = subparsers.add_parser("delete-scan", help="Delete a scan")
    add_shared_api_flags(delete)
    delete.add_argument("scan_id")
    delete.set_defaults(func=cmd_delete)

    e2e = subparsers.add_parser("e2e", help="Run the full create/start/stop/results/delete lifecycle")
    add_shared_api_flags(e2e)
    add_shared_feed_flags(e2e, include_output=False)
    e2e.add_argument(
        "--wait-before-results",
        type=_non_negative_float,
        default=_non_negative_float(os.environ.get("WAIT_BEFORE_RESULTS", "10")),
        help="Initial seconds to wait before polling for scan results",
    )
    e2e.add_argument(
        "--create-retries",
        type=int,
        default=int(os.environ.get("CREATE_SCAN_RETRIES", "12")),
        help="How many times to retry scan creation while the scanner API warms up",
    )
    e2e.add_argument(
        "--create-retry-delay",
        type=_non_negative_float,
        default=_non_negative_float(os.environ.get("CREATE_SCAN_RETRY_DELAY", "10")),
        help="Seconds to wait between scan creation retries",
    )
    e2e.add_argument(
        "--results-timeout",
        type=_non_negative_float,
        default=_non_negative_float(os.environ.get("RESULTS_TIMEOUT", "300")),
        help="Maximum seconds to wait for findings to appear",
    )
    e2e.add_argument(
        "--results-poll-interval",
        type=_non_negative_float,
        default=_non_negative_float(os.environ.get("RESULTS_POLL_INTERVAL", "15")),
        help="Seconds to wait between results polls",
    )
    e2e.set_defaults(func=cmd_e2e)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.func is None:
        parser.print_help(sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
