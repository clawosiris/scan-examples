from __future__ import annotations

import json
from pathlib import Path

from scan_examples.conversion import build_target_payload, convert_full_and_fast, discover_feed_layout


def test_build_target_payload_includes_ports():
    payload = build_target_payload(["target.local"], tcp_ports=[22, 80])

    assert payload["target"]["hosts"] == ["target.local"]
    assert payload["target"]["ports"][0]["range"] == [{"start": 22}, {"start": 80}]


def test_discover_feed_layout_resolves_nested_vt_path(tmp_path):
    vt_root = tmp_path / "vulnerability-tests"
    nested = vt_root / "24.10" / "vt-data" / "nasl"
    nested.mkdir(parents=True)
    (nested / "sha256sums").write_text("hashes")

    layout = discover_feed_layout(tmp_path / "data-objects", vt_root)

    assert layout.vt_path == nested


def test_convert_full_and_fast_invokes_scannerctl(tmp_path, monkeypatch):
    data_objects = tmp_path / "data-objects"
    vt_path = tmp_path / "vulnerability-tests"
    scan_configs = data_objects / "scan-configs"
    port_lists = data_objects / "port-lists"
    scan_configs.mkdir(parents=True)
    port_lists.mkdir(parents=True)
    vt_path.mkdir(parents=True)

    (scan_configs / "full-and-fast-daba56c8-73ec-11df-a475-002264764cea.xml").write_text("scan-config")
    (port_lists / "openvas-default-c7e03b6c-3bbe-11e1-a057-406186ea4fc5.xml").write_text("port-list")

    captured = {}

    class Result:
        returncode = 0
        stdout = json.dumps({"target": {"hosts": ["example"]}, "vts": [{"oid": "1.2.3"}]})
        stderr = ""

    def fake_run(command, input, text, capture_output, check):
        captured["command"] = command
        captured["input"] = json.loads(input)
        return Result()

    monkeypatch.setattr("scan_examples.conversion.subprocess.run", fake_run)

    payload = convert_full_and_fast(
        layout=discover_feed_layout(data_objects, vt_path),
        hosts=["example"],
        tcp_ports=[22],
        scannerctl_bin="scannerctl",
    )

    assert payload["vts"] == [{"oid": "1.2.3"}]
    assert captured["command"][0] == "scannerctl"
    assert captured["input"]["target"]["hosts"] == ["example"]
