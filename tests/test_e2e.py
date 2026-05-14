from __future__ import annotations

import pytest

from scan_examples.e2e import E2EResult, dump_result, run_lifecycle, summarize_results


class DummyClient:
    def __init__(self, results_sequence=None, status_sequence=None) -> None:
        self.calls: list[tuple[str, object]] = []
        self.results_sequence = list(results_sequence or [[
            {"id": 1, "oid": "1.2.3", "type": "alarm", "severity": "high"},
            {"id": 2, "type": "log", "cvss": 9.3},
        ]])
        self.status_sequence = list(status_sequence or [{"status": "running"}])

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

    def get_scan_status(self, scan_id: str):
        self.calls.append(("status", scan_id))
        if len(self.status_sequence) > 1:
            return self.status_sequence.pop(0)
        return self.status_sequence[0]

    def stop_scan(self, scan_id: str):
        self.calls.append(("stop", scan_id))
        return {"status": "stopped"}

    def delete_scan(self, scan_id: str):
        self.calls.append(("delete", scan_id))
        return {"status": "deleted"}


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


def test_dump_result_is_machine_readable():
    result = E2EResult(
        scan_id="scan-123",
        create_response={"id": "scan-123"},
        start_response={"status": "started"},
        stop_response={"status": "stopped"},
        final_status={"status": "stopped"},
        results=[{"id": 1, "type": "alarm"}],
        enriched_results=[
            {
                "id": 1,
                "type": "alarm",
                "feed-metadata-source": None,
                "vt-metadata-status": "missing_oid",
                "vt-metadata": None,
                "notus-metadata-status": "missing_oid",
                "notus-metadata": [],
            }
        ],
        findings_summary={"total": 1, "by_severity": {"unknown": 1}, "by_type": {"alarm": 1}},
        delete_response={"status": "deleted"},
    )

    rendered = dump_result(result)

    assert '"scan_id": "scan-123"' in rendered
    assert '"results": [' in rendered
    assert '"enriched_results": [' in rendered
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
    client = DummyClient(
        results_sequence=[
            [],
            [
                {"id": 1, "oid": "1.2.3", "type": "alarm", "severity": "high"},
                {"id": 2, "type": "log", "cvss": 9.3},
            ],
        ]
    )
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
        vt_index=VT_INDEX,
        progress=messages.append,
    )

    assert result.findings_summary["total"] == 2
    assert result.stop_response == {"status": "stopped"}
    assert result.final_status == {"status": "running"}
    assert result.delete_response == {"status": "deleted"}
    assert result.enriched_results[0]["feed-metadata-source"] == "vt"
    assert result.enriched_results[0]["vt-metadata-status"] == "matched"
    assert result.enriched_results[0]["notus-metadata-status"] == "metadata_unavailable"
    assert result.enriched_results[1]["vt-metadata-status"] == "missing_oid"
    assert result.enriched_results[1]["notus-metadata-status"] == "missing_oid"
    assert sleeps == [5]
    assert messages == [
        "Creating scan (attempt 1/12)",
        "Created scan scan-123",
        "Starting scan scan-123",
        "Fetching results for scan-123 (poll 1)",
        "No findings yet; waiting 5s before retrying",
        "Fetching results for scan-123 (poll 2)",
        "Findings increased from 0 to 2",
        "Fetched 2 findings",
        "Stopping scan scan-123",
        "Deleting scan scan-123",
        "Deleted scan scan-123",
    ]


def test_run_lifecycle_waits_for_minimum_first_results(monkeypatch):
    initial_results = [
        {"id": index, "type": "alarm", "severity": "high"} for index in range(1, 1000)
    ]
    enough_results = [
        {"id": index, "type": "alarm", "severity": "high"} for index in range(1, 1001)
    ]
    client = DummyClient(results_sequence=[initial_results, enough_results])
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
        min_results=1000,
        progress=messages.append,
    )

    assert result.findings_summary["total"] == 1000
    assert sleeps == [5]
    assert "Fetched 999 findings; waiting for at least 1000 before retrying in 5s" in messages


def test_run_lifecycle_can_wait_for_scan_completion(monkeypatch):
    client = DummyClient(
        results_sequence=[
            [{"id": 1, "oid": "1.2.3", "type": "alarm", "severity": "high"}],
            [
                {"id": 1, "oid": "1.2.3", "type": "alarm", "severity": "high"},
                {"id": 2, "type": "log"},
            ],
        ],
        status_sequence=[{"status": "running"}, {"status": "succeeded"}],
    )
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
        completion_mode="scan-complete",
        progress=messages.append,
    )

    assert result.findings_summary["total"] == 2
    assert result.final_status == {"status": "succeeded"}
    assert result.stop_response == {"status": "not_stopped", "reason": "scan_completed"}
    assert ("stop", "scan-123") not in client.calls
    assert sleeps == [5]
    assert "Scan still running after 1 findings; waiting 5s before retrying" in messages
    assert "Scan scan-123 status: succeeded" in messages


def test_run_lifecycle_stops_scan_when_findings_stall(monkeypatch):
    client = DummyClient(
        results_sequence=[
            [{"id": 1, "oid": "1.2.3", "type": "alarm", "severity": "high"}],
            [{"id": 1, "oid": "1.2.3", "type": "alarm", "severity": "high"}],
        ],
        status_sequence=[{"status": "running"}, {"status": "running"}],
    )
    messages: list[str] = []
    sleeps: list[float] = []
    monkeypatch.setattr("scan_examples.e2e.time.sleep", lambda seconds: sleeps.append(seconds))
    monotonic_values = iter([0.0, 1.0, 1502.0])
    monkeypatch.setattr("scan_examples.e2e.time.monotonic", lambda: next(monotonic_values))

    result = run_lifecycle(
        client=client,
        payload={"target": {}, "vts": []},
        wait_before_results=0,
        results_timeout=5400,
        results_poll_interval=30,
        no_findings_increment_timeout=1500,
        completion_mode="scan-complete",
        progress=messages.append,
    )

    assert result.findings_summary["total"] == 1
    assert result.stop_response == {"status": "stopped", "reason": "findings_stalled"}
    assert ("stop", "scan-123") in client.calls
    assert sleeps == [30]
    assert "No increase in findings for 1500s; stopping scan scan-123" in messages


def test_run_lifecycle_fails_when_completed_scan_has_no_findings(monkeypatch):
    client = DummyClient(results_sequence=[[]], status_sequence=[{"status": "succeeded"}])
    messages: list[str] = []
    monkeypatch.setattr("scan_examples.e2e.time.sleep", lambda seconds: None)
    monkeypatch.setattr("scan_examples.e2e.time.monotonic", lambda: 0.0)

    with pytest.raises(RuntimeError, match="completed without findings"):
        run_lifecycle(
            client=client,
            payload={"target": {}, "vts": []},
            wait_before_results=0,
            completion_mode="scan-complete",
            progress=messages.append,
        )

    assert ("delete", "scan-123") in client.calls


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
