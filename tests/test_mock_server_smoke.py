from __future__ import annotations

import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import pytest

from scan_examples.client import OpenVASScannerClient
from scan_examples.e2e import run_lifecycle
from scan_examples.enrichment import resolve_rust_enrichment_binary


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
    raise RuntimeError(
        f"mock server did not open port {port} within {timeout_seconds:.1f}s"
    )


def _wait_for_health(base_url: str, timeout_seconds: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    health_url = f"{base_url}/health/alive"
    while time.monotonic() < deadline:
        try:
            with urlopen(health_url, timeout=1.0) as response:
                payload = json.load(response)
            if payload.get("status") == "ok":
                return
        except (OSError, URLError, ValueError):
            pass
        time.sleep(0.1)
    raise RuntimeError(
        f"mock server did not become healthy at {health_url} within "
        f"{timeout_seconds:.1f}s"
    )


def _container_runtime() -> str | None:
    for candidate in ("docker", "podman"):
        if shutil.which(candidate):
            return candidate
    return None


def _mock_server_env(port: int) -> dict[str, str]:
    return {
        "MOCK_SCENARIO": "success-basic",
        "MOCK_RESULT_COUNT": "7",
        "MOCK_HOST_COUNT": "3",
        "MOCK_SEED": "scan-examples-smoke",
        "LISTENING": f"0.0.0.0:{port}",
        "MOCK_HOST": "0.0.0.0",
        "MOCK_PORT": str(port),
    }


def _write_matching_enrichment_inputs(
    raw_results: list[dict[str, object]], tmp_path: Path
) -> tuple[Path, Path]:
    vt_dir = tmp_path / "vt"
    vt_dir.mkdir()
    vt_metadata_path = vt_dir / "vt-metadata.json"
    scap_path = tmp_path / "scap.json"

    vt_entries: list[dict[str, object]] = []
    scap_entries: list[dict[str, object]] = []
    seen_cves: set[str] = set()
    for result in raw_results:
        oid = result.get("oid")
        if not isinstance(oid, str) or not oid:
            continue

        cve_refs: list[dict[str, str]] = []
        cve_ids = result.get("cve")
        if isinstance(cve_ids, list):
            for raw_cve in cve_ids:
                if not isinstance(raw_cve, str) or not raw_cve:
                    continue
                cve_refs.append({"class": "cve", "id": raw_cve})
                if raw_cve not in seen_cves:
                    seen_cves.add(raw_cve)
                    scap_entries.append(
                        {
                            "id": raw_cve,
                            "descriptions": [
                                {
                                    "lang": "en",
                                    "value": f"Fixture CVE description for {raw_cve}",
                                }
                            ],
                        }
                    )

        vt_entries.append(
            {
                "oid": oid,
                "name": result.get("nvt_name", f"Mock VT {oid}"),
                "family": result.get("family", "Synthetic Compatibility"),
                "category": "gather_info",
                "references": cve_refs,
                "tag": {"summary": result.get("description", "Mock fixture result")},
            }
        )

    vt_metadata_path.write_text(json.dumps(vt_entries), encoding="utf-8")
    scap_path.write_text(json.dumps(scap_entries), encoding="utf-8")
    return vt_dir, scap_path


@pytest.fixture(scope="module")
def mock_server_repo() -> Path | None:
    raw = os.environ.get("OPENVAS_MOCK_SANNER_REPO")
    if not raw:
        return None
    repo = Path(raw).resolve()
    module_entrypoint = repo / "openvas_mock_scanner" / "__main__.py"
    if not module_entrypoint.exists():
        pytest.skip(f"openvas_mock_scanner module not found under {repo}")
    return repo


@pytest.fixture(scope="module")
def mock_server_image() -> str | None:
    return os.environ.get("OPENVAS_MOCK_SCANNER_IMAGE")


@pytest.fixture
def mock_server(
    mock_server_image: str | None,
    mock_server_repo: Path | None,
):
    port = _choose_free_port()
    base_url = f"http://127.0.0.1:{port}"

    if mock_server_image:
        runtime = _container_runtime()
        if runtime is None:
            pytest.skip(
                "OPENVAS_MOCK_SCANNER_IMAGE is set but neither docker nor podman is available"
            )

        env = _mock_server_env(80)
        command = [
            runtime,
            "run",
            "--rm",
            "-d",
            "-p",
            f"{port}:80",
        ]
        for key, value in env.items():
            command.extend(["-e", f"{key}={value}"])
        command.append(mock_server_image)

        container = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
        container_id = container.stdout.strip()
        if not container_id:
            raise AssertionError(f"{runtime} run did not return a container id")

        try:
            _wait_for_port(port)
            _wait_for_health(base_url)
            yield base_url
        finally:
            with contextlib.suppress(subprocess.CalledProcessError):
                subprocess.run(
                    [runtime, "rm", "-f", container_id],
                    check=True,
                    capture_output=True,
                    text=True,
                )
        return

    if mock_server_repo is None:
        pytest.skip(
            "Set OPENVAS_MOCK_SCANNER_IMAGE for the published container smoke path "
            "or OPENVAS_MOCK_SANNER_REPO for a local source checkout"
        )

    env = os.environ.copy()
    env.update(_mock_server_env(port))
    process = subprocess.Popen(
        [sys.executable, "-m", "openvas_mock_scanner"],
        cwd=mock_server_repo,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for_port(port)
        _wait_for_health(base_url)
        yield base_url
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
    assert result.stop_response is None
    assert result.final_status is not None
    assert result.final_status["status"] in {
        "requested",
        "running",
        "stored",
        "succeeded",
    }


def test_cli_get_results_matches_between_python_and_rust_against_mock_server(
    mock_server: str, tmp_path: Path
):
    rust_bin = resolve_rust_enrichment_binary()
    if rust_bin is None:
        pytest.skip("scan-enrich-results Rust binary is not available")

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
    scan_id = json.loads(create.stdout)["scan_id"]

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

    client = OpenVASScannerClient(mock_server)
    raw_results = client.get_results(scan_id)
    assert len(raw_results) == 7
    vt_dir, scap_path = _write_matching_enrichment_inputs(raw_results, tmp_path)

    def run_get_results(engine: str) -> dict[str, object]:
        command = [
            sys.executable,
            "-m",
            "scan_examples.cli",
            "get-results",
            "--enrichment-engine",
            engine,
            "--vt-path",
            str(vt_dir),
            "--scap-path",
            str(scap_path),
            "--base-url",
            mock_server,
            scan_id,
        ]
        if engine == "rust":
            command.extend(["--rust-bin", str(rust_bin)])
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(completed.stdout)

    python_payload = run_get_results("python")
    rust_payload = run_get_results("rust")

    assert rust_payload == python_payload
    assert rust_payload["scan_id"] == scan_id
    assert len(rust_payload["results"]) == 7
    assert len(rust_payload["enriched_results"]) == 7
    assert all(
        result["vt-metadata-status"] == "matched"
        for result in rust_payload["enriched_results"]
    )
    assert any(
        result["cve-metadata-status"] == "matched"
        for result in rust_payload["enriched_results"]
    )

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
