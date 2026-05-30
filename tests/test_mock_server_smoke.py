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
from scan_examples.feed import load_vt_metadata_index


MOCK_FEED_FIXTURE_DIR = Path(__file__).parent / "data" / "mock-feed"
MOCK_CONTAINER_FEED_DIR = "/mock-feed"


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


def _mock_server_env(
    port: int,
    *,
    scenario: str = "success-basic",
    result_count: int = 7,
    host_count: int = 3,
    page_size: int = 100,
    seed: str = "scan-examples-smoke",
    feed_fixture_dir: str | Path | None = None,
) -> dict[str, str]:
    env = {
        "MOCK_SCENARIO": scenario,
        "MOCK_RESULT_COUNT": str(result_count),
        "MOCK_HOST_COUNT": str(host_count),
        "MOCK_PAGE_SIZE": str(page_size),
        "MOCK_SEED": "scan-examples-smoke",
        "LISTENING": f"0.0.0.0:{port}",
        "MOCK_HOST": "0.0.0.0",
        "MOCK_PORT": str(port),
    }
    env["MOCK_SEED"] = seed
    if feed_fixture_dir is not None:
        root = Path(feed_fixture_dir)
        env.update(
            {
                "MOCK_VT_METADATA_PATH": str(root / "vt-metadata.json"),
                "MOCK_TARGET_PROFILE": str(root / "target-profile.json"),
                "MOCK_NOTUS_ADVISORIES_PATH": str(root / "notus-advisories.json"),
                "MOCK_SCAP_METADATA_PATH": str(root / "scap-cves.json"),
                "MOCK_FEED_STRICT": "true",
            }
        )
    return env


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
    request: pytest.FixtureRequest,
    mock_server_image: str | None,
    mock_server_repo: Path | None,
):
    options = getattr(request, "param", {}) or {}
    port = _choose_free_port()
    base_url = f"http://127.0.0.1:{port}"
    feed_backed = bool(options.get("feed_backed"))

    if mock_server_image:
        runtime = _container_runtime()
        if runtime is None:
            pytest.skip(
                "OPENVAS_MOCK_SCANNER_IMAGE is set but neither docker nor podman is available"
            )

        env = _mock_server_env(
            80,
            scenario=options.get("scenario", "success-basic"),
            result_count=options.get("result_count", 7),
            host_count=options.get("host_count", 3),
            page_size=options.get("page_size", 100),
            seed=options.get("seed", "scan-examples-smoke"),
            feed_fixture_dir=MOCK_CONTAINER_FEED_DIR if feed_backed else None,
        )
        command = [
            runtime,
            "run",
            "--rm",
            "-d",
            "-p",
            f"{port}:80",
        ]
        if feed_backed:
            command.extend(
                [
                    "-v",
                    f"{MOCK_FEED_FIXTURE_DIR}:{MOCK_CONTAINER_FEED_DIR}:ro",
                ]
            )
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
    env.update(
        _mock_server_env(
            port,
            scenario=options.get("scenario", "success-basic"),
            result_count=options.get("result_count", 7),
            host_count=options.get("host_count", 3),
            page_size=options.get("page_size", 100),
            seed=options.get("seed", "scan-examples-smoke"),
            feed_fixture_dir=MOCK_FEED_FIXTURE_DIR if feed_backed else None,
        )
    )
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


@pytest.mark.parametrize(
    "mock_server",
    [
        {
            "feed_backed": True,
            "scenario": "success-large-report",
            "result_count": 125,
            "host_count": 2,
            "page_size": 50,
            "seed": "scan-examples-feed",
        }
    ],
    indirect=True,
)
def test_mock_server_feed_backed_compatibility(mock_server: str):
    _, vt_index = load_vt_metadata_index(MOCK_FEED_FIXTURE_DIR / "vt-metadata.json")
    selected_oids = [
        "1.3.6.1.4.1.25623.1.0.100034",
        "1.3.6.1.4.1.25623.1.0.147696",
        "1.3.6.1.4.1.25623.1.0.117812",
        "1.3.6.1.4.1.25623.1.0.900001",
    ]

    with urlopen(f"{mock_server}/feed/diagnostics", timeout=1.0) as response:
        diagnostics = json.load(response)
    assert diagnostics["metadata_count"] == len(vt_index)
    assert diagnostics["target_profile_hosts"] == 2
    assert diagnostics["notus_advisories"] == 1
    assert diagnostics["scap_cves"] == 2
    assert diagnostics["diagnostics"] == []

    with urlopen(f"{mock_server}/vts/{selected_oids[2]}", timeout=1.0) as response:
        vt_metadata = json.load(response)
    assert vt_metadata["name"].startswith("Apache HTTP Server")
    assert "CVE-2021-41773" in vt_metadata["cves"]

    client = OpenVASScannerClient(mock_server)
    result = run_lifecycle(
        client=client,
        payload={
            "scan_id": "scan-examples-feed",
            "target": {"hosts": ["192.0.2.10"], "ports": "T:22,80,443"},
            "vts": [{"oid": oid} for oid in selected_oids],
        },
        wait_before_results=0,
        create_retry_delay=0,
        results_timeout=10,
        results_poll_interval=0.1,
        min_results=125,
        vt_index=vt_index,
    )

    result_oids = {finding["oid"] for finding in result.results}
    assert result.findings_summary["total"] == 125
    assert result_oids == set(selected_oids)
    assert {finding["id"] for finding in result.results} == set(range(125))
    assert result.findings_summary["by_type"]["alarm"] > 0
    assert result.findings_summary["by_type"]["log"] > 0
    assert all(
        enriched["feed-metadata-source"] == "vt" for enriched in result.enriched_results
    )
    assert all(
        enriched["vt-metadata-status"] == "matched"
        for enriched in result.enriched_results
    )


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
            "--enrichment-engine",
            "python",
            scan_id,
            "--base-url",
            mock_server,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    results_payload = json.loads(results.stdout)
    assert results_payload["scan_id"] == scan_id
    assert len(results_payload["results"]) == 7
    assert len(results_payload["enriched_results"]) == 7

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
