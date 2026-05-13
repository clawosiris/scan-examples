from __future__ import annotations

import json
from pathlib import Path

from scan_examples.conversion import build_target_payload, convert_full_and_fast, convert_scan_config, discover_feed_layout


def test_build_target_payload_includes_ports():
    payload = build_target_payload(["target.local"], tcp_ports=[22, 80])

    assert payload["target"]["hosts"] == ["target.local"]
    assert payload["target"]["ports"][0]["range"] == [{"start": 22}, {"start": 80}]


def test_build_target_payload_omits_ports_without_override():
    payload = build_target_payload(["target.local"], tcp_ports=None)

    assert payload["target"] == {"hosts": ["target.local"]}


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
    assert "-l" in captured["command"]


def test_convert_full_and_fast_generates_portlist_from_tcp_ports(tmp_path, monkeypatch):
    data_objects = tmp_path / "data-objects"
    vt_path = tmp_path / "vulnerability-tests"
    scan_configs = data_objects / "scan-configs"
    scan_configs.mkdir(parents=True)
    vt_path.mkdir(parents=True)

    (scan_configs / "full-and-fast-daba56c8-73ec-11df-a475-002264764cea.xml").write_text("scan-config")

    captured = {}

    class Result:
        returncode = 0
        stdout = json.dumps({"target": {"hosts": ["example"]}, "vts": [{"oid": "1.2.3"}]})
        stderr = ""

    def fake_run(command, input, text, capture_output, check):
        captured["command"] = command
        captured["input"] = json.loads(input)
        portlist_path = Path(command[command.index("-l") + 1])
        captured["portlist_xml"] = portlist_path.read_text()
        return Result()

    monkeypatch.setattr("scan_examples.conversion.subprocess.run", fake_run)

    payload = convert_full_and_fast(
        layout=discover_feed_layout(data_objects, vt_path),
        hosts=["example"],
        tcp_ports=[80],
        scannerctl_bin="scannerctl",
    )

    assert payload["vts"] == [{"oid": "1.2.3"}]
    assert captured["command"][0] == "scannerctl"
    assert "-l" in captured["command"]
    assert "<start>80</start>" in captured["portlist_xml"]
    assert captured["input"]["target"]["ports"][0]["range"] == [{"start": 80}]


def test_convert_scan_config_uses_scan_default_ports_without_tcp_ports(tmp_path, monkeypatch):
    data_objects = tmp_path / "data-objects"
    vt_path = tmp_path / "vulnerability-tests"
    scan_configs = data_objects / "scan-configs"
    scan_configs.mkdir(parents=True)
    vt_path.mkdir(parents=True)

    (scan_configs / "full-and-fast-daba56c8-73ec-11df-a475-002264764cea.xml").write_text("scan-config")

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

    payload = convert_scan_config(
        layout=discover_feed_layout(data_objects, vt_path),
        hosts=["example"],
        scan_config="full-and-fast",
        tcp_ports=None,
        scannerctl_bin="scannerctl",
    )

    assert payload["vts"] == [{"oid": "1.2.3"}]
    assert captured["command"][0] == "scannerctl"
    assert "-l" not in captured["command"]
    assert "ports" not in captured["input"]["target"]


def test_convert_scan_config_retries_with_legacy_scannerctl_cli(tmp_path, monkeypatch):
    data_objects = tmp_path / "data-objects"
    vt_path = tmp_path / "vulnerability-tests"
    scan_configs = data_objects / "scan-configs"
    scan_configs.mkdir(parents=True)
    vt_path.mkdir(parents=True)

    (scan_configs / "full-and-fast-daba56c8-73ec-11df-a475-002264764cea.xml").write_text("scan-config")

    calls = []

    class LegacyErrorResult:
        returncode = 2
        stdout = ""
        stderr = "error: unexpected argument '-i' found"

    class SuccessResult:
        returncode = 0
        stdout = json.dumps({"target": {"hosts": ["example"]}, "vts": [{"oid": "1.2.3"}]})
        stderr = ""

    def fake_run(command, input, text, capture_output, check):
        calls.append(command)
        if len(calls) == 1:
            return LegacyErrorResult()
        return SuccessResult()

    monkeypatch.setattr("scan_examples.conversion.subprocess.run", fake_run)

    payload = convert_scan_config(
        layout=discover_feed_layout(data_objects, vt_path),
        hosts=["example"],
        scan_config="full-and-fast",
        tcp_ports=[80],
        scannerctl_bin="scannerctl",
    )

    assert payload["vts"] == [{"oid": "1.2.3"}]
    assert calls[0][2:4] == ["-i", "-p"]
    assert calls[1][2] == "-s"


def test_convert_scan_config_resolves_named_scan_config(tmp_path, monkeypatch):
    data_objects = tmp_path / "data-objects"
    vt_path = tmp_path / "vulnerability-tests"
    scan_configs = data_objects / "scan-configs"
    scan_configs.mkdir(parents=True)
    vt_path.mkdir(parents=True)

    (scan_configs / "custom-scan.xml").write_text("scan-config")

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

    payload = convert_scan_config(
        layout=discover_feed_layout(data_objects, vt_path),
        hosts=["example"],
        scan_config="custom-scan",
        tcp_ports=None,
        scannerctl_bin="scannerctl",
    )

    assert payload["vts"] == [{"oid": "1.2.3"}]
    assert captured["command"][-1].endswith("custom-scan.xml")
