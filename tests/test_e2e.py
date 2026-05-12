from __future__ import annotations

from scan_examples.e2e import E2EResult, dump_result, run_lifecycle, summarize_results


class DummyClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

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
    monkeypatch.setattr("scan_examples.e2e.time.sleep", lambda _seconds: None)

    result = run_lifecycle(
        client=client,
        payload={"target": {}, "vts": []},
        wait_before_results=0,
        progress=messages.append,
    )

    assert result.findings_summary["total"] == 2
    assert messages == [
        "Creating scan (attempt 1/12)",
        "Created scan scan-123",
        "Starting scan scan-123",
        "Waiting 0s before collecting results",
        "Stopping scan scan-123",
        "Fetching results for scan-123",
        "Fetched 2 findings",
        "Deleting scan scan-123",
        "Deleted scan scan-123",
    ]
