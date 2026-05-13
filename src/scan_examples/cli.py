from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable

from .client import OpenVASScannerClient
from .conversion import convert_scan_config, discover_feed_layout, load_custom_scan_config
from .e2e import dump_result, run_lifecycle
from .feed import dump_pretty_enriched_results, enrich_results, load_scap_cve_index, load_vt_metadata_index


E2E_FALLBACK_TCP_PORTS = [21, 22, 80, 139, 445, 3306]
DEFAULT_TARGET_SSH_USERNAME = "msfadmin"
DEFAULT_TARGET_SSH_PASSWORD = "msfadmin"
DEFAULT_TARGET_SSH_PORT = 22


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


def _load_scap_index_for_cli(scap_path: str | None, progress: Callable[[str], None] | None = None) -> dict[str, dict[str, Any]] | None:
    if not scap_path:
        return None
    try:
        paths, cve_index = load_scap_cve_index(scap_path)
    except FileNotFoundError:
        if progress is not None:
            progress(f"SCAP data not found under {scap_path}; continuing without CVE enrichment")
        return None
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        if progress is not None:
            progress(f"Failed to load SCAP CVE data from {scap_path}: {exc}; continuing without CVE enrichment")
        return None

    if progress is not None:
        progress(f"Loaded {len(cve_index)} CVE records from {len(paths)} SCAP file(s)")
    return cve_index


def _load_vt_index_for_cli(vt_path: str, progress: Callable[[str], None] | None = None) -> dict[str, dict[str, Any]] | None:
    try:
        metadata_path, vt_index = load_vt_metadata_index(vt_path)
    except FileNotFoundError:
        if progress is not None:
            progress(f"VT metadata file not found under {vt_path}; continuing without enrichment")
        return None
    except (json.JSONDecodeError, ValueError) as exc:
        if progress is not None:
            progress(f"Failed to load VT metadata from {vt_path}: {exc}; continuing without enrichment")
        return None

    if progress is not None:
        progress(f"Loaded VT metadata index from {metadata_path}")
    return vt_index


def _convert_with_fallback(
    *,
    layout,
    hosts: list[str],
    scan_config: str,
    tcp_ports: list[int],
    ssh_username: str | None,
    ssh_password: str | None,
    ssh_port: int,
    scannerctl_bin: str,
    progress: Callable[[str], None] | None = None,
):
    try:
        return convert_scan_config(
            layout=layout,
            hosts=hosts,
            scan_config=scan_config,
            tcp_ports=tcp_ports,
            ssh_username=ssh_username,
            ssh_password=ssh_password,
            ssh_port=ssh_port,
            scannerctl_bin=scannerctl_bin,
        )
    except FileNotFoundError:
        if tcp_ports:
            raise
        if progress is not None:
            progress(
                "Feed default port list was not found; falling back to bundled metasploitable service ports "
                f"{', '.join(str(port) for port in E2E_FALLBACK_TCP_PORTS)}"
            )
        return convert_scan_config(
            layout=layout,
            hosts=hosts,
            scan_config=scan_config,
            tcp_ports=E2E_FALLBACK_TCP_PORTS,
            ssh_username=ssh_username,
            ssh_password=ssh_password,
            ssh_port=ssh_port,
            scannerctl_bin=scannerctl_bin,
        )



def cmd_convert(args: argparse.Namespace) -> int:
    tcp_ports = _parse_ports(args.tcp_ports)
    if args.scan_config_json:
        payload = load_custom_scan_config(
            args.scan_config_json,
            hosts=args.host,
            tcp_ports=tcp_ports,
            ssh_username=args.ssh_username,
            ssh_password=args.ssh_password,
            ssh_port=args.ssh_port,
        )
    else:
        layout = discover_feed_layout(args.data_objects_path, args.vt_path)
        payload = _convert_with_fallback(
            layout=layout,
            hosts=args.host,
            scan_config=args.scan_config,
            tcp_ports=tcp_ports,
            ssh_username=args.ssh_username,
            ssh_password=args.ssh_password,
            ssh_port=args.ssh_port,
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
    scap_cve_index = _load_scap_index_for_cli(args.scap_path)
    _dump_json(
        {
            "scan_id": args.scan_id,
            "results": results,
            "enriched_results": enrich_results(results, vt_index, scap_cve_index),
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
    ports_rendered = ", ".join(str(port) for port in tcp_ports) if tcp_ports else "default ports from the scan config"
    progress(f"Target hosts: {', '.join(args.host)}")
    progress(f"Scanning TCP ports: {ports_rendered}")
    if args.scan_config_json:
        progress(f"Using custom scan config JSON: {args.scan_config_json}")
    else:
        progress(f"Using scan config: {args.scan_config}")
    if args.ssh_username and args.ssh_password:
        progress(f"Using SSH credential for {args.ssh_username}@{', '.join(args.host)}:{args.ssh_port}")
    else:
        progress("No SSH credential configured for the target")
    progress("Discovering Greenbone community feed layout")
    layout = discover_feed_layout(args.data_objects_path, args.vt_path)
    vt_index = _load_vt_index_for_cli(layout.vt_path, progress=progress)
    scap_cve_index = _load_scap_index_for_cli(args.scap_path, progress=progress)
    if args.scan_config_json:
        progress("Loading custom scan configuration JSON")
        payload = load_custom_scan_config(
            args.scan_config_json,
            hosts=args.host,
            tcp_ports=tcp_ports,
            ssh_username=args.ssh_username,
            ssh_password=args.ssh_password,
            ssh_port=args.ssh_port,
        )
    else:
        progress("Converting scan configuration with scannerctl")
        payload = _convert_with_fallback(
            layout=layout,
            hosts=args.host,
            scan_config=args.scan_config,
            tcp_ports=tcp_ports,
            ssh_username=args.ssh_username,
            ssh_password=args.ssh_password,
            ssh_port=args.ssh_port,
            scannerctl_bin=args.scannerctl_bin,
            progress=progress,
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
        no_findings_increment_timeout=args.no_findings_increment_timeout,
        completion_mode=args.completion_mode,
        vt_index=vt_index,
        scap_cve_index=scap_cve_index,
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

    def add_scap_path_flag(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--scap-path",
            default=os.environ.get("SCAP_PATH"),
            help="Optional path to Greenbone/NVD SCAP CVE JSON data for CVE enrichment",
        )

    def add_scan_config_flag(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--scan-config",
            default=os.environ.get("SCAN_CONFIG", "full-and-fast"),
            help="Scan configuration to convert (default: full-and-fast)",
        )

    def add_shared_feed_flags(command: argparse.ArgumentParser, *, include_output: bool = True) -> None:
        command.add_argument(
            "--data-objects-path",
            default=os.environ.get("DATA_OBJECTS_PATH", "/feed/data-objects"),
            help="Path to the Greenbone data-objects feed",
        )
        add_vt_path_flag(command)
        add_scap_path_flag(command)
        add_scan_config_flag(command)
        command.add_argument(
            "--scan-config-json",
            default=os.environ.get("SCAN_CONFIG_JSON"),
            help="Path to a custom scanner API scan config JSON payload, or a zip containing one JSON file",
        )
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
            default=os.environ.get("TARGET_TCP_PORTS"),
            help="Comma-separated list of TCP ports for the target; omit to use the scan config defaults",
        )
        command.add_argument(
            "--ssh-username",
            default=os.environ.get("TARGET_SSH_USERNAME", DEFAULT_TARGET_SSH_USERNAME),
            help="SSH username to include in the scan target credentials",
        )
        command.add_argument(
            "--ssh-password",
            default=os.environ.get("TARGET_SSH_PASSWORD", DEFAULT_TARGET_SSH_PASSWORD),
            help="SSH password to include in the scan target credentials",
        )
        command.add_argument(
            "--ssh-port",
            type=int,
            default=int(os.environ.get("TARGET_SSH_PORT", str(DEFAULT_TARGET_SSH_PORT))),
            help="SSH port to include in the scan target credentials",
        )
        if include_output:
            command.add_argument("--output", help="Write JSON output to a file")

    subparsers = parser.add_subparsers(dest="command")

    convert = subparsers.add_parser("convert-config", help="Convert a scan config to scan JSON")
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
    add_scap_path_flag(results)
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
    e2e.add_argument(
        "--no-findings-increment-timeout",
        type=_non_negative_float,
        default=_non_negative_float(os.environ.get("E2E_NO_FINDINGS_INCREMENT_TIMEOUT", "0")),
        help="For scan-complete mode, stop after this many seconds without an increase in finding count; 0 disables",
    )
    e2e.add_argument(
        "--completion-mode",
        choices=["first-results", "scan-complete"],
        default=os.environ.get("E2E_COMPLETION_MODE", "first-results"),
        help="Stop after first findings for quick checks, or wait for natural scan completion",
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
