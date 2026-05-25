from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from scan_examples.client import OpenVASScannerClient
from scan_examples.e2e import run_lifecycle


def _choose_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, timeout_seconds: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.25)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"mock server did not open port {port} within {timeout_seconds:.1f}s")


@pytest.fixture(scope="module")
def mock_server_repo() -> Path:
    raw = os.environ.get("OPENVAS_MOCK_SANNER_REPO")
    if not raw:
        pytest.skip("OPENVAS_MOCK_SANNER_REPO is not set")
    repo = Path(raw).resolve()
    if not repo.exists():
        pytest.skip(f"OPENVAS_MOCK_SANNER_REPO does not exist: {repo}")
    cargo_toml = repo / "implementations" / "baseline-rust" / "Cargo.toml"
    if not cargo_toml.exists():
        pytest.skip(f"baseline-rust implementation not found under {repo}")
    return repo


@pytest.fixture
def mock_server(mock_server_repo: Path):
    port = _choose_free_port()
    implementation_dir = mock_server_repo / "implementations" / "baseline-rust"
    env = os.environ.copy()
    env.update(
        {
            "PORT": str(port),
            "MOCK_RESULT_COUNT": "7",
            "MOCK_FINDINGS_DELAY_POLLS": "2",
            "MOCK_SCAN_COMPLETE_POLLS": "3",
            "MOCK_HOST_COUNT": "3",
            "MOCK_SEED": "scan-examples-smoke",
        }
    )
    process = subprocess.Popen(
        ["cargo", "run", "--quiet"],
        cwd=implementation_dir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for_port(port)
        yield f"http://127.0.0.1:{port}"
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        if process.returncode not in (0, -15):
            stderr = process.stderr.read() if process.stderr is not None else ""
            stdout = process.stdout.read() if process.stdout is not None else ""
            raise AssertionError(
                "mock server exited unexpectedly\n"
                f"returncode={process.returncode}\nstdout={stdout}\nstderr={stderr}"
            )


def test_mock_server_smoke_lifecycle(mock_server: str):
    client = OpenVASScannerClient(mock_server)
    result = run_lifecycle(
        client=client,
        payload={"target": {"hosts": ["target"]}, "vts": []},
        wait_before_results=0,
        create_retry_delay=0,
        results_timeout=10,
        results_poll_interval=0.1,
        min_results=7,
    )

    assert result.scan_id
    assert result.findings_summary["total"] == 7
    assert result.stop_response["status"] == "stopped"
    assert result.final_status["status"] == "running"


def test_cli_commands_work_against_mock_server(mock_server: str, tmp_path: Path):
    scan_path = tmp_path / "scan.json"
    scan_path.write_text(
        json.dumps({"target": {"hosts": ["target"]}, "vts": []}),
        encoding="utf-8",
    )

    create = subprocess.run(
        [
            sys.executable,
            "-m",
            "scan_examples.cli",
            "create-scan",
            str(scan_path),
            "--base-url",
            mock_server,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    create_payload = json.loads(create.stdout)
    scan_id = create_payload["scan_id"]

    subprocess.run(
        [
            sys.executable,
            "-m",
            "scan_examples.cli",
            "start-scan",
            scan_id,
            "--base-url",
            mock_server,
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    results = subprocess.run(
        [
            sys.executable,
            "-m",
            "scan_examples.cli",
            "get-results",
            scan_id,
            "--base-url",
            mock_server,
            "--vt-path",
            str(tmp_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    results_payload = json.loads(results.stdout)
    assert results_payload["scan_id"] == scan_id
    assert results_payload["results"] == []
    assert results_payload["enriched_results"] == []

    delete = subprocess.run(
        [
            sys.executable,
            "-m",
            "scan_examples.cli",
            "delete-scan",
            scan_id,
            "--base-url",
            mock_server,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    delete_payload = json.loads(delete.stdout)
    assert delete_payload["scan_id"] == scan_id
    assert delete_payload["deleted"] is True
