import json
from pathlib import Path

from scan_examples.conversion import (
    build_target_payload,
    convert_full_and_fast,
    convert_scan_config,
    discover_feed_layout,
    load_custom_scan_config,
)


FULL_AND_FAST = "full-and-fast-daba56c8-73ec-11df-a475-002264764cea.xml"
DEFAULT_PORTLIST = "openvas-default-c7e03b6c-3bbe-11e1-a057-406186ea4fc5.xml"


def test_build_target_payload_includes_ports():
    payload = build_target_payload(["target.local"], tcp_ports=[22, 80])

    assert payload["target"]["hosts"] == ["target.local"]
    assert payload["target"]["ports"][0]["range"] == [{"start": 22}, {"start": 80}]


def test_build_target_payload_omits_ports_without_override():
    payload = build_target_payload(["target.local"], tcp_ports=None)

    assert payload["target"] == {"hosts": ["target.local"]}


def test_build_target_payload_includes_ssh_credentials():
    payload = build_target_payload(
        ["target.local"],
        tcp_ports=[22],
        ssh_username="msfadmin",
        ssh_password="msfadmin",
        ssh_port=22,
    )

    assert payload["target"]["credentials"] == [
        {
            "service": "ssh",
            "port": 22,
            "up": {"username": "msfadmin", "password": "msfadmin"},
        }
    ]


def test_load_custom_scan_config_overrides_hosts_and_credentials(tmp_path):
    custom_config = tmp_path / "scan.json"
    custom_config.write_text(
        json.dumps(
            {
                "target": {
                    "hosts": [],
                    "ports": [
                        {"protocol": "tcp", "range": [{"start": 1, "end": 65535}]}
                    ],
                    "credentials": [],
                },
                "vts": [{"oid": "1.2.3", "parameters": []}],
            }
        )
    )

    payload = load_custom_scan_config(
        custom_config,
        hosts=["target"],
        ssh_username="msfadmin",
        ssh_password="msfadmin",
        ssh_port=22,
    )

    assert payload["target"]["hosts"] == ["target"]
    assert payload["target"]["ports"] == [
        {"protocol": "tcp", "range": [{"start": 1, "end": 65535}]}
    ]
    assert payload["target"]["credentials"] == [
        {
            "service": "ssh",
            "port": 22,
            "up": {"username": "msfadmin", "password": "msfadmin"},
        }
    ]
    assert payload["vts"] == [{"oid": "1.2.3", "parameters": []}]


def test_load_custom_scan_config_can_override_ports_from_zip(tmp_path):
    import zipfile

    archive_path = tmp_path / "scan.zip"
    payload = {
        "target": {
            "hosts": [],
            "ports": [{"protocol": "tcp", "range": [{"start": 1, "end": 65535}]}],
        },
        "vts": [],
    }
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("scan.json", json.dumps(payload))
        archive.writestr("__MACOSX/._scan.json", "metadata")

    loaded = load_custom_scan_config(archive_path, hosts=["target"], tcp_ports=[22, 80])

    assert loaded["target"]["hosts"] == ["target"]
    assert loaded["target"]["ports"] == [
        {"protocol": "tcp", "range": [{"start": 22}, {"start": 80}]}
    ]


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

    (scan_configs / FULL_AND_FAST).write_text("scan-config")
    (port_lists / DEFAULT_PORTLIST).write_text("port-list")

    captured = {}

    class Result:
        returncode = 0
        stdout = json.dumps(
            {"target": {"hosts": ["example"]}, "vts": [{"oid": "1.2.3"}]}
        )
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
        ssh_username="msfadmin",
        ssh_password="msfadmin",
        scannerctl_bin="scannerctl",
    )

    assert payload["vts"] == [{"oid": "1.2.3"}]
    assert captured["command"][0] == "scannerctl"
    assert captured["input"]["target"]["hosts"] == ["example"]
    assert captured["input"]["target"]["credentials"] == [
        {
            "service": "ssh",
            "port": 22,
            "up": {"username": "msfadmin", "password": "msfadmin"},
        }
    ]
    assert "-l" in captured["command"]
    assert captured["command"][-1].endswith(FULL_AND_FAST)


def test_convert_full_and_fast_generates_portlist_from_tcp_ports(tmp_path, monkeypatch):
    data_objects = tmp_path / "data-objects"
    vt_path = tmp_path / "vulnerability-tests"
    scan_configs = data_objects / "scan-configs"
    scan_configs.mkdir(parents=True)
    vt_path.mkdir(parents=True)

    (scan_configs / FULL_AND_FAST).write_text("scan-config")

    captured = {}

    class Result:
        returncode = 0
        stdout = json.dumps(
            {"target": {"hosts": ["example"]}, "vts": [{"oid": "1.2.3"}]}
        )
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
    assert captured["command"][-1].endswith(FULL_AND_FAST)


def test_convert_scan_config_uses_feed_default_portlist_without_tcp_ports(
    tmp_path, monkeypatch
):
    data_objects = tmp_path / "data-objects"
    vt_path = tmp_path / "vulnerability-tests"
    scan_configs = data_objects / "scan-configs"
    port_lists = data_objects / "port-lists"
    scan_configs.mkdir(parents=True)
    port_lists.mkdir(parents=True)
    vt_path.mkdir(parents=True)

    (scan_configs / FULL_AND_FAST).write_text("scan-config")
    (port_lists / DEFAULT_PORTLIST).write_text("port-list")

    captured = {}

    class Result:
        returncode = 0
        stdout = json.dumps(
            {"target": {"hosts": ["example"]}, "vts": [{"oid": "1.2.3"}]}
        )
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
    assert "-l" in captured["command"]
    assert "ports" not in captured["input"]["target"]
    assert captured["command"][-1].endswith(FULL_AND_FAST)


def test_convert_scan_config_retries_with_legacy_scannerctl_cli(tmp_path, monkeypatch):
    data_objects = tmp_path / "data-objects"
    vt_path = tmp_path / "vulnerability-tests"
    scan_configs = data_objects / "scan-configs"
    scan_configs.mkdir(parents=True)
    vt_path.mkdir(parents=True)

    (scan_configs / FULL_AND_FAST).write_text("scan-config")

    calls = []

    class LegacyErrorResult:
        returncode = 2
        stdout = ""
        stderr = "error: unexpected argument '-i' found"

    class SuccessResult:
        returncode = 0
        stdout = json.dumps(
            {"target": {"hosts": ["example"]}, "vts": [{"oid": "1.2.3"}]}
        )
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
    assert calls[0][-1].endswith(FULL_AND_FAST)


def test_convert_scan_config_resolves_named_scan_config(tmp_path, monkeypatch):
    data_objects = tmp_path / "data-objects"
    vt_path = tmp_path / "vulnerability-tests"
    scan_configs = data_objects / "scan-configs"
    port_lists = data_objects / "port-lists"
    scan_configs.mkdir(parents=True)
    port_lists.mkdir(parents=True)
    vt_path.mkdir(parents=True)

    (scan_configs / "custom-scan.xml").write_text("scan-config")
    (port_lists / DEFAULT_PORTLIST).write_text("port-list")

    captured = {}

    class Result:
        returncode = 0
        stdout = json.dumps(
            {"target": {"hosts": ["example"]}, "vts": [{"oid": "1.2.3"}]}
        )
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
