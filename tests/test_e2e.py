from __future__ import annotations

from scan_examples.e2e import E2EResult, dump_result


def test_dump_result_is_machine_readable():
    result = E2EResult(
        scan_id="scan-123",
        create_response={"id": "scan-123"},
        start_response={"status": "started"},
        stop_response={"status": "stopped"},
        results=[{"id": 1, "type": "alarm"}],
        delete_response={"status": "deleted"},
    )

    rendered = dump_result(result)

    assert '"scan_id": "scan-123"' in rendered
    assert '"results": [' in rendered
