from __future__ import annotations

from scan_examples.cli import build_parser


def test_build_parser_supports_e2e_command():
    parser = build_parser()

    args = parser.parse_args([
        "e2e",
        "--output",
        "result.json",
        "--host",
        "target",
        "--create-retries",
        "3",
        "--results-timeout",
        "600",
        "--results-poll-interval",
        "15",
    ])

    assert args.command == "e2e"
    assert args.host == ["target"]
    assert args.output == "result.json"
    assert args.create_retries == 3
    assert args.results_timeout == 600
    assert args.results_poll_interval == 15
