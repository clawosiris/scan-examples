from __future__ import annotations

import pytest

from scan_examples.e2e import E2EResult, dump_result, run_lifecycle, summarize_results


class DummyClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.result_calls = 0

    def create_scan(self, payload):
        self.calls.append(("create", payload))
        return "scan-123"

    def start_scan(self, scan_id: str):
        self.calls.append(("start", scan_id))
        return {"status": "started"}

    def stop_scan(self, scan_id: str):
        self.calls.append(("stop", scan_id))
        return {"status": "stopped"}

    def get_results(self, scan_id: str):
        self.calls.append(("results", scan_id))
        self.result_calls += 1
        if self.result_calls < 3:
            return []
        return [
            {"id": 1, "type": "alarm", "severity": "high"},
            {"id": 2, "type": "log", "cvss": 9.3},
        ]

    def delete_scan(self, scan_id: str):
        self.calls.append(("delete", scan_id))
        return {"status": "deleted"}


def test_dump_result_is_machine_readable():
    result = E2EResult(
        scan_id="scan-123",
        create_response={"id": "scan-123"},
        start_response={"status": "started"},
        stop_response={"status": "stopped"},
        results=[{"id": 1, "type": "alarm"}],
        findings_summary={"total": 1, "by_severity": {"unknown": 1}, "by_type": {"alarm": 1}},
        delete_response={"status": "deleted"},
    )

    rendered = dump_result(result)

    assert '"scan_id": "scan-123"' in rendered
    assert '"results": [' in rendered
    assert '"findings_summary": {' in rendered


def test_summarize_results_counts_findings():
    summary = summarize_results(
        [
            {"id": 1, "type": "alarm", "severity": "high"},
            {"id": 2, "type": "alarm", "cvss": 9.1},
            {"id": 3, "type": "log", "threat": "medium"},
            {"id": 4},
        ]
    )

    assert summary == {
        "total": 4,
        "by_severity": {"high": 1, "critical": 1, "medium": 1, "unknown": 1},
        "by_type": {"alarm": 2, "log": 1, "unknown": 1},
    }


def test_run_lifecycle_emits_progress_in_order(monkeypatch):
    client = DummyClient()
    messages: list[str] = []
    monotonic_values = iter([0.0, 1.0, 2.0])

    monkeypatch.setattr("scan_examples.e2e.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("scan_examples.e2e.time.monotonic", lambda: next(monotonic_values))

    result = run_lifecycle(
        client=client,
        payload={"target": {}, "vts": []},
        wait_before_results=0,
        progress=messages.append,
        results_timeout=300,
        results_poll_interval=30,
    )

    assert result.findings_summary["total"] == 2
    assert messages == [
        "Creating scan (attempt 1/12)",
        "Created scan scan-123",
        "Starting scan scan-123",
        "Initial wait 0s before polling for results",
        "Fetching results for scan-123 (poll 1)",
        "No findings yet; waiting 30s before retrying",
        "Fetching results for scan-123 (poll 2)",
        "No findings yet; waiting 30s before retrying",
        "Fetching results for scan-123 (poll 3)",
        "Fetched 2 findings",
        "Stopping scan scan-123",
        "Deleting scan scan-123",
        "Deleted scan scan-123",
    ]


def test_run_lifecycle_stops_and_deletes_on_timeout(monkeypatch):
    stopped: list[str] = []
    deleted: list[str] = []

    class Client:
        def create_scan(self, payload):
            return "scan-123"

        def start_scan(self, scan_id):
            return {"status": "started"}

        def get_results(self, scan_id):
            return []

        def stop_scan(self, scan_id):
            stopped.append(scan_id)
            return {"status": "stopped"}

        def delete_scan(self, scan_id):
            deleted.append(scan_id)
            return {"status": "deleted"}

    monotonic_values = iter([0.0, 301.0])

    monkeypatch.setattr("scan_examples.e2e.time.sleep", lambda seconds: None)
    monkeypatch.setattr("scan_examples.e2e.time.monotonic", lambda: next(monotonic_values))

    with pytest.raises(RuntimeError, match="Timed out after 300"):
        run_lifecycle(
            client=Client(),
            payload={"target": {}},
            results_timeout=300,
            results_poll_interval=30,
        )

    assert stopped == ["scan-123"]
    assert deleted == ["scan-123"]
