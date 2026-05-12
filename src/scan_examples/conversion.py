from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

FULL_AND_FAST_FILENAMES = [
    "full-and-fast-daba56c8-73ec-11df-a475-002264764cea.xml",
    "full-and-fast.xml",
]
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


def convert_full_and_fast(
    *,
    layout: FeedLayout,
    hosts: list[str],
    tcp_ports: list[int] | None = None,
    scannerctl_bin: str = "scannerctl",
) -> dict[str, Any]:
    scan_config = _first_existing(layout.data_objects_path, FULL_AND_FAST_FILENAMES)
    try:
        portlist = _first_existing(layout.data_objects_path, OPENVAS_DEFAULT_PORTLIST_FILENAMES)
    except FileNotFoundError:
        portlist = None
    base_payload = build_target_payload(hosts, tcp_ports=tcp_ports)

    command = [
        scannerctl_bin,
        "scan-config",
        "-i",
        "-p",
        str(layout.vt_path),
    ]
    if portlist is not None:
        command.extend(["-l", str(portlist)])
    command.append(str(scan_config))

    result = subprocess.run(
        command,
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
