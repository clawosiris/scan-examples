from __future__ import annotations

from pathlib import Path

import pytest

from scan_examples import cli
from scan_examples.cli import build_parser


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


def test_cmd_e2e_logs_scanned_ports(monkeypatch, capsys, tmp_path):
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

    class DummyClient:
        pass

    monkeypatch.setattr(cli, "_build_client", lambda _args: DummyClient())

    class DummyResult:
        findings_summary = {"total": 0, "by_severity": {}, "by_type": {}}

    monkeypatch.setattr(cli, "run_lifecycle", lambda **_kwargs: DummyResult())
    monkeypatch.setattr(cli, "dump_result", lambda _result: '{"ok": true}')

    assert cli.cmd_e2e(args) == 0

    captured = capsys.readouterr()
    assert "[e2e] Scanning TCP ports: 22, 80, 445" in captured.err
    assert Path(output_path).read_text(encoding="utf-8") == '{"ok": true}\n'


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
