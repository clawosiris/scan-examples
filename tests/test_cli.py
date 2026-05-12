from __future__ import annotations

import json
from pathlib import Path

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


def test_build_parser_supports_e2e_command():
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


def test_build_parser_uses_metasploitable_port_defaults():
    parser = build_parser()

    args = parser.parse_args([
        "e2e",
        "--host",
        "target",
    ])

    assert args.tcp_ports == "21,22,80,139,445,3306"


def test_cmd_e2e_logs_scanned_ports_and_enriched_findings(monkeypatch, capsys, tmp_path):
    parser = build_parser()
    output_path = tmp_path / "result.json"
    args = parser.parse_args([
        "e2e",
        "--host",
        "target",
        "--tcp-ports",
        "22,80,445",
        "--output",
        str(output_path),
    ])

    monkeypatch.setattr(cli, "discover_feed_layout", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli, "convert_full_and_fast", lambda **_kwargs: {"target": {}, "vts": []})
    monkeypatch.setattr(cli, "_load_vt_index_for_cli", lambda _vt_path, progress=None: VT_INDEX)

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
    assert "[e2e] Scanning TCP ports: 22, 80, 445" in captured.err
    assert "[e2e] Enriched findings:" in captured.err
    assert '"vt_metadata_status": "matched"' in captured.err
    assert Path(output_path).read_text(encoding="utf-8") == '{"ok": true}\n'


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


def test_load_vt_index_for_cli_soft_fails_on_invalid_json(capsys):
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
