from __future__ import annotations

import pytest

from scan_examples.e2e import E2EResult, dump_result, run_lifecycle, summarize_results


class DummyClient:
    def __init__(self, results_sequence=None) -> None:
        self.calls: list[tuple[str, object]] = []
        self.results_sequence = list(results_sequence or [[
            {"id": 1, "type": "alarm", "severity": "high"},
            {"id": 2, "type": "log", "cvss": 9.3},
        ]])

    def create_scan(self, payload):
        self.calls.append(("create", payload))
        return "scan-123"

    def start_scan(self, scan_id: str):
        self.calls.append(("start", scan_id))
        return {"status": "started"}

    def get_results(self, scan_id: str):
        self.calls.append(("results", scan_id))
        if len(self.results_sequence) > 1:
            return self.results_sequence.pop(0)
        return self.results_sequence[0]

    def stop_scan(self, scan_id: str):
        self.calls.append(("stop", scan_id))
        return {"status": "stopped"}

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
    client = DummyClient(results_sequence=[[], [{"id": 1, "type": "alarm", "severity": "high"}, {"id": 2, "type": "log", "cvss": 9.3}]])
    messages: list[str] = []
    sleeps: list[float] = []
    monkeypatch.setattr("scan_examples.e2e.time.sleep", lambda seconds: sleeps.append(seconds))
    monotonic_values = iter([0.0, 1.0, 2.0])
    monkeypatch.setattr("scan_examples.e2e.time.monotonic", lambda: next(monotonic_values))

    result = run_lifecycle(
        client=client,
        payload={"target": {}, "vts": []},
        wait_before_results=0,
        results_timeout=60,
        results_poll_interval=5,
        progress=messages.append,
    )

    assert result.findings_summary["total"] == 2
    assert result.stop_response == {"status": "stopped"}
    assert result.delete_response == {"status": "deleted"}
    assert sleeps == [5]
    assert messages == [
        "Creating scan (attempt 1/12)",
        "Created scan scan-123",
        "Starting scan scan-123",
        "Fetching results for scan-123 (poll 1)",
        "No findings yet; waiting 5s before retrying",
        "Fetching results for scan-123 (poll 2)",
        "Fetched 2 findings",
        "Stopping scan scan-123",
        "Deleting scan scan-123",
        "Deleted scan scan-123",
    ]


def test_run_lifecycle_stops_and_deletes_on_timeout(monkeypatch):
    client = DummyClient(results_sequence=[[]])
    messages: list[str] = []
    monkeypatch.setattr("scan_examples.e2e.time.sleep", lambda _seconds: None)
    monotonic_values = iter([0.0, 301.0])
    monkeypatch.setattr("scan_examples.e2e.time.monotonic", lambda: next(monotonic_values))

    with pytest.raises(RuntimeError, match="Timed out after 300s waiting for findings"):
        run_lifecycle(
            client=client,
            payload={"target": {}, "vts": []},
            wait_before_results=0,
            results_timeout=300,
            results_poll_interval=30,
            progress=messages.append,
        )

    assert client.calls == [
        ("create", {"target": {}, "vts": []}),
        ("start", "scan-123"),
        ("results", "scan-123"),
        ("stop", "scan-123"),
        ("delete", "scan-123"),
    ]
    assert messages == [
        "Creating scan (attempt 1/12)",
        "Created scan scan-123",
        "Starting scan scan-123",
        "Fetching results for scan-123 (poll 1)",
        "No findings before timeout; stopping scan scan-123",
        "Stopping scan scan-123",
        "Deleting scan scan-123",
        "Deleted scan scan-123",
    ]


def test_run_lifecycle_clamps_negative_poll_interval(monkeypatch):
    client = DummyClient(results_sequence=[[], [{"id": 1, "type": "alarm", "severity": "high"}]])
    messages: list[str] = []
    monkeypatch.setattr("scan_examples.e2e.time.sleep", lambda _seconds: None)
    monotonic_values = iter([0.0, 1.0, 2.0])
    monkeypatch.setattr("scan_examples.e2e.time.monotonic", lambda: next(monotonic_values))

    run_lifecycle(
        client=client,
        payload={"target": {}, "vts": []},
        wait_before_results=0,
        results_timeout=60,
        results_poll_interval=-5,
        progress=messages.append,
    )

    assert "No findings yet; waiting 0s before retrying" in messages
