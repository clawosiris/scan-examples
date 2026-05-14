"""Helpers for turning feed data and scanner configs into scan payloads."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import zipfile
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
    """Resolved feed directories needed for config conversion."""

    data_objects_path: Path
    vt_path: Path


def _first_existing(root: Path, candidates: list[str]) -> Path:
    """Return the first matching file under ``root`` from a candidate list."""
    for candidate in candidates:
        matches = list(root.rglob(candidate))
        if matches:
            return matches[0]
    raise FileNotFoundError(f"Could not find any of {candidates!r} under {root}")


def _resolve_vt_path(root: Path) -> Path:
    """Resolve the actual VT feed directory from a broad mount path.

    Compose mounts may point at the VT directory itself or at a parent
    directory that contains it, so we search for the usual marker files.
    """
    if (root / "sha256sums").exists() or (root / "vt-metadata.json").exists():
        return root
    for marker in ("sha256sums", "vt-metadata.json"):
        matches = list(root.rglob(marker))
        if matches:
            return matches[0].parent
    return root


def discover_feed_layout(data_objects_path: str | os.PathLike[str], vt_path: str | os.PathLike[str]) -> FeedLayout:
    """Build a :class:`FeedLayout` from the configured feed paths."""
    return FeedLayout(data_objects_path=Path(data_objects_path), vt_path=_resolve_vt_path(Path(vt_path)))


def build_target_payload(
    hosts: list[str],
    tcp_ports: list[int] | None = None,
    *,
    ssh_username: str | None = None,
    ssh_password: str | None = None,
    ssh_port: int = 22,
) -> dict[str, Any]:
    """Build the target portion of a scanner payload.

    This is the minimal structure needed by ``scannerctl`` and the direct JSON
    payload path used by the examples.
    """
    target: dict[str, Any] = {"hosts": hosts}
    if tcp_ports:
        target["ports"] = _build_tcp_port_ranges(tcp_ports)
    if ssh_username and ssh_password:
        target["credentials"] = [
            {
                "service": "ssh",
                "port": int(ssh_port),
                "up": {"username": ssh_username, "password": ssh_password},
            }
        ]
    return {"target": target, "vts": []}


def _build_tcp_port_ranges(tcp_ports: list[int]) -> list[dict[str, Any]]:
    """Translate a flat port list into the scanner API range structure."""
    return [{"protocol": "tcp", "range": [{"start": int(port)} for port in tcp_ports]}]


def _apply_target_overrides(
    payload: dict[str, Any],
    *,
    hosts: list[str],
    tcp_ports: list[int] | None = None,
    ssh_username: str | None = None,
    ssh_password: str | None = None,
    ssh_port: int = 22,
) -> dict[str, Any]:
    """Apply host, port, and credential overrides to a custom payload template."""
    updated = json.loads(json.dumps(payload))
    target = updated.setdefault("target", {})
    if not isinstance(target, dict):
        raise ValueError("Custom scan config payload must contain an object target")
    target["hosts"] = hosts
    if tcp_ports:
        target["ports"] = _build_tcp_port_ranges(tcp_ports)
    if ssh_username and ssh_password:
        target["credentials"] = [
            {
                "service": "ssh",
                "port": int(ssh_port),
                "up": {"username": ssh_username, "password": ssh_password},
            }
        ]
    return updated


def load_custom_scan_config(
    path: str | os.PathLike[str],
    *,
    hosts: list[str],
    tcp_ports: list[int] | None = None,
    ssh_username: str | None = None,
    ssh_password: str | None = None,
    ssh_port: int = 22,
) -> dict[str, Any]:
    """Load a custom scan payload from JSON or a zip archive.

    The zip support is mainly for exported scanner payloads that bundle exactly
    one JSON file.
    """
    scan_config_path = Path(path)
    if scan_config_path.suffix == ".zip":
        with zipfile.ZipFile(scan_config_path) as archive:
            candidates = [
                name
                for name in archive.namelist()
                if not name.endswith("/")
                and not name.startswith("__MACOSX/")
                and Path(name).suffix == ".json"
            ]
            if len(candidates) != 1:
                raise ValueError(
                    f"Expected exactly one JSON scan config in {scan_config_path}, found {len(candidates)}"
                )
            with archive.open(candidates[0]) as handle:
                payload = json.load(handle)
    else:
        payload = json.loads(scan_config_path.read_text(encoding="utf-8"))

    if not isinstance(payload, dict):
        raise ValueError("Custom scan config payload must be a JSON object")
    if not isinstance(payload.get("vts"), list):
        raise ValueError("Custom scan config payload must contain a vts list")
    return _apply_target_overrides(
        payload,
        hosts=hosts,
        tcp_ports=tcp_ports,
        ssh_username=ssh_username,
        ssh_password=ssh_password,
        ssh_port=ssh_port,
    )


def _write_portlist_xml(tcp_ports: list[int]) -> Path:
    """Create a temporary scannerctl-compatible XML port list file."""
    ranges = "\n".join(
        f'''    <port_range id="generated-{index}">\n      <start>{int(port)}</start>\n      <end>{int(port)}</end>\n      <type>tcp</type>\n      <comment/>\n    </port_range>'''
        for index, port in enumerate(tcp_ports, start=1)
    )
    xml = f'''<port_list id="generated-openvas-example">\n  <name>Generated OpenVAS Example Port List</name>\n  <comment>Generated from requested TCP ports.</comment>\n  <port_ranges>\n{ranges}\n  </port_ranges>\n</port_list>\n'''
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as handle:
        handle.write(xml)
        return Path(handle.name)


def _resolve_scan_config_path(layout: FeedLayout, scan_config: str) -> Path:
    """Resolve a scan config alias, file name, or explicit path."""
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
    """Build modern and legacy ``scannerctl scan-config`` command variants."""
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
    """Return ``True`` when scannerctl rejected the modern CLI syntax."""
    return "unexpected argument '-i'" in stderr or "unexpected argument '-p'" in stderr


def convert_scan_config(
    *,
    layout: FeedLayout,
    hosts: list[str],
    scan_config: str = "full-and-fast",
    tcp_ports: list[int] | None = None,
    ssh_username: str | None = None,
    ssh_password: str | None = None,
    ssh_port: int = 22,
    scannerctl_bin: str = "scannerctl",
) -> dict[str, Any]:
    """Convert a feed-backed scan configuration into scanner API JSON.

    The implementation first tries the modern ``scannerctl`` flag layout and
    falls back to an older syntax for compatibility with older tool builds.
    """
    scan_config_path = _resolve_scan_config_path(layout, scan_config)
    generated_portlist: Path | None = None
    if tcp_ports:
        generated_portlist = _write_portlist_xml(tcp_ports)
        portlist = generated_portlist
    else:
        portlist = _first_existing(layout.data_objects_path, OPENVAS_DEFAULT_PORTLIST_FILENAMES)
    base_payload = build_target_payload(
        hosts,
        tcp_ports=tcp_ports,
        ssh_username=ssh_username,
        ssh_password=ssh_password,
        ssh_port=ssh_port,
    )

    try:
        commands = _build_scannerctl_commands(
            scannerctl_bin=scannerctl_bin,
            vt_path=layout.vt_path,
            portlist=portlist,
            scan_config=scan_config_path,
        )
        # Feed the target JSON via stdin so scannerctl can merge it with the
        # scan config definition from the Greenbone feed data.
        result = subprocess.run(
            commands[0],
            input=json.dumps(base_payload),
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0 and _is_legacy_scannerctl_syntax_error(result.stderr):
            # Older scannerctl releases use a different argument layout. Try
            # that variant before giving up so the example is friendlier across
            # container versions.
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
    ssh_username: str | None = None,
    ssh_password: str | None = None,
    ssh_port: int = 22,
    scannerctl_bin: str = "scannerctl",
) -> dict[str, Any]:
    """Convenience wrapper for the repo's default ``full-and-fast`` profile."""
    return convert_scan_config(
        layout=layout,
        hosts=hosts,
        scan_config="full-and-fast",
        tcp_ports=tcp_ports,
        ssh_username=ssh_username,
        ssh_password=ssh_password,
        ssh_port=ssh_port,
        scannerctl_bin=scannerctl_bin,
    )
