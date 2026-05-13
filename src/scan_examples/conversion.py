from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCAN_CONFIG_ALIASES = {
    "full-and-fast": [
        "full-and-fast-daba56c8-73ec-11df-a475-002264764cea.xml",
        "full-and-fast.xml",
    ],
}
OPENVAS_DEFAULT_PORTLIST_FILENAMES = [
    "openvas-default-c7e03b6c-3bbe-11e1-a057-406186ea4fc5.xml",
    "openvas-default.xml",
]


class ScanConfigConversionError(RuntimeError):
    """Raised when scannerctl conversion fails."""


@dataclass(slots=True)
class FeedLayout:
    data_objects_path: Path
    vt_path: Path


def _first_existing(root: Path, candidates: list[str]) -> Path:
    for candidate in candidates:
        matches = list(root.rglob(candidate))
        if matches:
            return matches[0]
    raise FileNotFoundError(f"Could not find any of {candidates!r} under {root}")


def _resolve_vt_path(root: Path) -> Path:
    if (root / "sha256sums").exists() or (root / "vt-metadata.json").exists():
        return root
    for marker in ("sha256sums", "vt-metadata.json"):
        matches = list(root.rglob(marker))
        if matches:
            return matches[0].parent
    return root


def discover_feed_layout(data_objects_path: str | os.PathLike[str], vt_path: str | os.PathLike[str]) -> FeedLayout:
    return FeedLayout(data_objects_path=Path(data_objects_path), vt_path=_resolve_vt_path(Path(vt_path)))


def build_target_payload(hosts: list[str], tcp_ports: list[int] | None = None) -> dict[str, Any]:
    port_ranges = []
    if tcp_ports:
        for port in tcp_ports:
            port_ranges.append({"start": int(port)})
    return {
        "target": {
            "hosts": hosts,
            "ports": [{"protocol": "tcp", "range": port_ranges}] if port_ranges else [],
        },
        "vts": [],
    }


def _write_portlist_xml(tcp_ports: list[int]) -> Path:
    ranges = "\n".join(
        f'''    <port_range id="generated-{index}">\n      <start>{int(port)}</start>\n      <end>{int(port)}</end>\n      <type>tcp</type>\n      <comment/>\n    </port_range>'''
        for index, port in enumerate(tcp_ports, start=1)
    )
    xml = f'''<port_list id="generated-openvas-example">\n  <name>Generated OpenVAS Example Port List</name>\n  <comment>Generated from requested TCP ports.</comment>\n  <port_ranges>\n{ranges}\n  </port_ranges>\n</port_list>\n'''
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as handle:
        handle.write(xml)
        return Path(handle.name)


def _resolve_scan_config_path(layout: FeedLayout, scan_config: str) -> Path:
    alias_candidates = SCAN_CONFIG_ALIASES.get(scan_config)
    if alias_candidates is not None:
        return _first_existing(layout.data_objects_path, alias_candidates)

    requested = Path(scan_config)
    if requested.is_absolute() and requested.is_file():
        return requested

    direct_candidates = [scan_config]
    if requested.suffix != ".xml":
        direct_candidates.append(f"{scan_config}.xml")
    try:
        return _first_existing(layout.data_objects_path, direct_candidates)
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"Could not resolve scan config {scan_config!r} under {layout.data_objects_path}"
        ) from exc


def _build_scannerctl_commands(
    *,
    scannerctl_bin: str,
    vt_path: Path,
    portlist: Path | None,
    scan_config: Path,
) -> list[list[str]]:
    modern = [scannerctl_bin, "scan-config", "-i", "-p", str(vt_path)]
    if portlist is not None:
        modern.extend(["-l", str(portlist)])
    modern.append(str(scan_config))

    legacy = [scannerctl_bin, "scan-config", "-s", str(vt_path)]
    if portlist is not None:
        legacy.append(str(portlist))
    legacy.append(str(scan_config))
    return [modern, legacy]


def _is_legacy_scannerctl_syntax_error(stderr: str) -> bool:
    return "unexpected argument '-i'" in stderr or "unexpected argument '-p'" in stderr


def convert_scan_config(
    *,
    layout: FeedLayout,
    hosts: list[str],
    scan_config: str = "full-and-fast",
    tcp_ports: list[int] | None = None,
    scannerctl_bin: str = "scannerctl",
) -> dict[str, Any]:
    scan_config_path = _resolve_scan_config_path(layout, scan_config)
    generated_portlist: Path | None = None
    if tcp_ports:
        generated_portlist = _write_portlist_xml(tcp_ports)
        portlist = generated_portlist
    else:
        try:
            portlist = _first_existing(layout.data_objects_path, OPENVAS_DEFAULT_PORTLIST_FILENAMES)
        except FileNotFoundError:
            portlist = None
    base_payload = build_target_payload(hosts, tcp_ports=tcp_ports)

    try:
        commands = _build_scannerctl_commands(
            scannerctl_bin=scannerctl_bin,
            vt_path=layout.vt_path,
            portlist=portlist,
            scan_config=scan_config_path,
        )
        result = subprocess.run(
            commands[0],
            input=json.dumps(base_payload),
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0 and _is_legacy_scannerctl_syntax_error(result.stderr):
            result = subprocess.run(
                commands[1],
                input=json.dumps(base_payload),
                text=True,
                capture_output=True,
                check=False,
            )
        if result.returncode != 0:
            raise ScanConfigConversionError(
                "scannerctl scan-config failed with exit code "
                f"{result.returncode}: {result.stderr.strip()}"
            )

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ScanConfigConversionError(
                f"scannerctl returned invalid JSON: {result.stdout[:500]}"
            ) from exc
    finally:
        if generated_portlist is not None:
            generated_portlist.unlink(missing_ok=True)


def convert_full_and_fast(
    *,
    layout: FeedLayout,
    hosts: list[str],
    tcp_ports: list[int] | None = None,
    scannerctl_bin: str = "scannerctl",
) -> dict[str, Any]:
    return convert_scan_config(
        layout=layout,
        hosts=hosts,
        scan_config="full-and-fast",
        tcp_ports=tcp_ports,
        scannerctl_bin=scannerctl_bin,
    )
