from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scan_examples import cli
from scan_examples.cli import build_parser


VT_INDEX = {
    "1.2.3": {
        "oid": "1.2.3",
        "name": "Example VT",
        "filename": "example.nasl",
        "family": "General",
        "category": "gather_info",
        "references": [{"class": "cve", "id": "CVE-2026-0001"}],
        "tag": {"summary": "Example summary"},
    }
}


def test_build_parser_supports_e2e_command(monkeypatch):
    monkeypatch.delenv("SCAP_PATH", raising=False)
    parser = build_parser()

    args = parser.parse_args([
        "e2e",
        "--host",
        "target",
        "--output",
        "result.json",
        "--create-retries",
        "3",
    ])

    assert args.command == "e2e"
    assert args.host == ["target"]
    assert args.output == "result.json"
    assert args.create_retries == 3
    assert args.results_timeout == 300
    assert args.results_poll_interval == 15
    assert args.completion_mode == "first-results"
    assert args.scan_config == "full-and-fast"
    assert args.scan_config_json is None
    assert args.scap_path is None
    assert args.tcp_ports is None
    assert args.ssh_username == "msfadmin"
    assert args.ssh_password == "msfadmin"
    assert args.ssh_port == 22


def test_cmd_e2e_logs_default_ports_and_scan_config(monkeypatch, capsys, tmp_path):
    parser = build_parser()
    output_path = tmp_path / "result.json"
    args = parser.parse_args([
        "e2e",
        "--host",
        "target",
        "--output",
        str(output_path),
    ])

    monkeypatch.setattr(cli, "discover_feed_layout", lambda *_args, **_kwargs: SimpleNamespace(vt_path=Path("/tmp/vt")))
    monkeypatch.setattr(cli, "convert_scan_config", lambda **_kwargs: {"target": {}, "vts": []})
    monkeypatch.setattr(cli, "_load_vt_index_for_cli", lambda _vt_path, progress=None: VT_INDEX)
    monkeypatch.setattr(cli, "_load_scap_index_for_cli", lambda _scap_path, progress=None: None)

    class DummyClient:
        pass

    monkeypatch.setattr(cli, "_build_client", lambda _args: DummyClient())

    class DummyResult:
        findings_summary = {"total": 1, "by_severity": {"high": 1}, "by_type": {"alarm": 1}}
        enriched_results = [
            {
                "result": {"id": 1, "oid": "1.2.3", "type": "alarm"},
                "vt_metadata_status": "matched",
                "vt_metadata": {"name": "Example VT"},
            }
        ]

    monkeypatch.setattr(cli, "run_lifecycle", lambda **_kwargs: DummyResult())
    monkeypatch.setattr(cli, "dump_result", lambda _result: '{"ok": true}')

    assert cli.cmd_e2e(args) == 0

    captured = capsys.readouterr()
    assert "[e2e] Scanning TCP ports: default ports from the scan config" in captured.err
    assert "[e2e] Using scan config: full-and-fast" in captured.err
    assert "[e2e] Using SSH credential for msfadmin@target:22" in captured.err
    assert "[e2e] Enriched findings:" in captured.err
    assert Path(output_path).read_text(encoding="utf-8") == '{"ok": true}\n'


def test_cmd_e2e_falls_back_to_bundled_ports_when_feed_default_portlist_is_missing(monkeypatch, tmp_path, capsys):
    parser = build_parser()
    output_path = tmp_path / "result.json"
    args = parser.parse_args([
        "e2e",
        "--host",
        "target",
        "--output",
        str(output_path),
    ])

    attempts = []
    monkeypatch.setattr(cli, "discover_feed_layout", lambda *_args, **_kwargs: SimpleNamespace(vt_path=Path("/tmp/vt")))
    monkeypatch.setattr(cli, "_load_vt_index_for_cli", lambda _vt_path, progress=None: VT_INDEX)

    def fake_convert_scan_config(**kwargs):
        attempts.append(kwargs)
        if len(attempts) == 1:
            raise FileNotFoundError("missing default port list")
        return {"target": {}, "vts": []}

    monkeypatch.setattr(cli, "convert_scan_config", fake_convert_scan_config)
    monkeypatch.setattr(cli, "_build_client", lambda _args: object())

    class DummyResult:
        findings_summary = {"total": 0, "by_severity": {}, "by_type": {}}
        enriched_results = []

    monkeypatch.setattr(cli, "run_lifecycle", lambda **_kwargs: DummyResult())
    monkeypatch.setattr(cli, "dump_result", lambda _result: '{"ok": true}')

    assert cli.cmd_e2e(args) == 0
    assert attempts[0]["tcp_ports"] == []
    assert attempts[0]["ssh_username"] == "msfadmin"
    assert attempts[0]["ssh_password"] == "msfadmin"
    assert attempts[0]["ssh_port"] == 22
    assert attempts[1]["tcp_ports"] == [21, 22, 80, 139, 445, 3306]
    assert "falling back to bundled metasploitable service ports" in capsys.readouterr().err


def test_cmd_e2e_passes_custom_scan_config_and_ports(monkeypatch, tmp_path):
    parser = build_parser()
    output_path = tmp_path / "result.json"
    args = parser.parse_args([
        "e2e",
        "--host",
        "target",
        "--scan-config",
        "custom-scan",
        "--tcp-ports",
        "22,80,445",
        "--ssh-username",
        "custom-user",
        "--ssh-password",
        "custom-pass",
        "--ssh-port",
        "2222",
        "--output",
        str(output_path),
    ])

    captured = {}
    monkeypatch.setattr(cli, "discover_feed_layout", lambda *_args, **_kwargs: SimpleNamespace(vt_path=Path("/tmp/vt")))
    monkeypatch.setattr(cli, "_load_vt_index_for_cli", lambda _vt_path, progress=None: VT_INDEX)

    def fake_convert_scan_config(**kwargs):
        captured.update(kwargs)
        return {"target": {}, "vts": []}

    monkeypatch.setattr(cli, "convert_scan_config", fake_convert_scan_config)
    monkeypatch.setattr(cli, "_build_client", lambda _args: object())

    class DummyResult:
        findings_summary = {"total": 0, "by_severity": {}, "by_type": {}}
        enriched_results = []

    monkeypatch.setattr(cli, "run_lifecycle", lambda **_kwargs: DummyResult())
    monkeypatch.setattr(cli, "dump_result", lambda _result: '{"ok": true}')

    assert cli.cmd_e2e(args) == 0
    assert captured["scan_config"] == "custom-scan"
    assert captured["tcp_ports"] == [22, 80, 445]
    assert captured["ssh_username"] == "custom-user"
    assert captured["ssh_password"] == "custom-pass"
    assert captured["ssh_port"] == 2222


def test_cmd_e2e_uses_custom_scan_config_json(monkeypatch, tmp_path, capsys):
    parser = build_parser()
    custom_scan_config = tmp_path / "scan.json"
    custom_scan_config.write_text('{"target": {"hosts": []}, "vts": []}')
    output_path = tmp_path / "result.json"
    args = parser.parse_args([
        "e2e",
        "--host",
        "target",
        "--scan-config-json",
        str(custom_scan_config),
        "--tcp-ports",
        "22",
        "--output",
        str(output_path),
    ])

    captured = {}
    monkeypatch.setattr(cli, "discover_feed_layout", lambda *_args, **_kwargs: SimpleNamespace(vt_path=Path("/tmp/vt")))
    monkeypatch.setattr(cli, "_load_vt_index_for_cli", lambda _vt_path, progress=None: VT_INDEX)

    def fake_load_custom_scan_config(path, **kwargs):
        captured["path"] = path
        captured.update(kwargs)
        return {"target": {"hosts": kwargs["hosts"]}, "vts": []}

    monkeypatch.setattr(cli, "load_custom_scan_config", fake_load_custom_scan_config)
    monkeypatch.setattr(cli, "convert_scan_config", lambda **_kwargs: (_ for _ in ()).throw(AssertionError("scannerctl path should not run")))
    monkeypatch.setattr(cli, "_build_client", lambda _args: object())

    class DummyResult:
        findings_summary = {"total": 0, "by_severity": {}, "by_type": {}}
        enriched_results = []

    monkeypatch.setattr(cli, "run_lifecycle", lambda **_kwargs: DummyResult())
    monkeypatch.setattr(cli, "dump_result", lambda _result: '{"ok": true}')

    assert cli.cmd_e2e(args) == 0
    assert captured["path"] == str(custom_scan_config)
    assert captured["hosts"] == ["target"]
    assert captured["tcp_ports"] == [22]
    assert captured["ssh_username"] == "msfadmin"
    assert "[e2e] Using custom scan config JSON:" in capsys.readouterr().err


def test_cmd_results_emits_enriched_json(monkeypatch, capsys):
    parser = build_parser()
    args = parser.parse_args([
        "get-results",
        "scan-123",
    ])

    class DummyClient:
        def get_results(self, scan_id):
            assert scan_id == "scan-123"
            return [{"id": 1, "oid": "1.2.3", "type": "alarm"}]

    monkeypatch.setattr(cli, "_build_client", lambda _args: DummyClient())
    monkeypatch.setattr(cli, "_load_vt_index_for_cli", lambda _vt_path, progress=None: VT_INDEX)

    assert cli.cmd_results(args) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["scan_id"] == "scan-123"
    assert payload["enriched_results"][0]["vt_metadata_status"] == "matched"
    assert payload["enriched_results"][0]["vt_metadata"]["name"] == "Example VT"


def test_load_vt_index_for_cli_soft_fails_on_invalid_json():
    messages: list[str] = []

    def broken_loader(_vt_path):
        raise json.JSONDecodeError("bad json", "{", 1)

    original_loader = cli.load_vt_metadata_index
    cli.load_vt_metadata_index = broken_loader
    try:
        assert cli._load_vt_index_for_cli("/tmp/vt", progress=messages.append) is None
    finally:
        cli.load_vt_metadata_index = original_loader

    assert messages == [
        "Failed to load VT metadata from /tmp/vt: bad json: line 1 column 2 (char 1); continuing without enrichment"
    ]


def test_load_vt_index_for_cli_soft_fails_on_invalid_shape():
    messages: list[str] = []

    def broken_loader(_vt_path):
        raise ValueError("Unsupported VT metadata payload shape")

    original_loader = cli.load_vt_metadata_index
    cli.load_vt_metadata_index = broken_loader
    try:
        assert cli._load_vt_index_for_cli("/tmp/vt", progress=messages.append) is None
    finally:
        cli.load_vt_metadata_index = original_loader

    assert messages == [
        "Failed to load VT metadata from /tmp/vt: Unsupported VT metadata payload shape; continuing without enrichment"
    ]


def test_build_parser_rejects_negative_poll_interval():
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args([
            "e2e",
            "--host",
            "target",
            "--results-poll-interval",
            "-1",
        ])


def test_build_parser_rejects_negative_timeout():
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args([
            "e2e",
            "--host",
            "target",
            "--results-timeout",
            "-1",
        ])
