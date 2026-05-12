from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from .client import OpenVASAPIError, OpenVASScannerClient


@dataclass(slots=True)
class E2EResult:
    scan_id: str
    create_response: Any
    start_response: Any
    stop_response: Any
    results: list[dict[str, Any]]
    delete_response: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "create_response": self.create_response,
            "start_response": self.start_response,
            "stop_response": self.stop_response,
            "results": self.results,
            "delete_response": self.delete_response,
        }


def run_lifecycle(
    *,
    client: OpenVASScannerClient,
    payload: dict[str, Any],
    wait_before_results: float = 10.0,
    create_retries: int = 12,
    create_retry_delay: float = 10.0,
) -> E2EResult:
    last_error: Exception | None = None
    for attempt in range(1, create_retries + 1):
        try:
            scan_id = client.create_scan(payload)
            break
        except (OpenVASAPIError, OSError) as exc:
            last_error = exc
            if attempt == create_retries:
                raise
            time.sleep(create_retry_delay)
    else:
        raise RuntimeError(f"Failed to create scan after {create_retries} attempts: {last_error}")
    create_response = {"id": scan_id}
    start_response = client.start_scan(scan_id)
    time.sleep(wait_before_results)
    stop_response = client.stop_scan(scan_id)
    results = client.get_results(scan_id)
    delete_response = client.delete_scan(scan_id)
    return E2EResult(
        scan_id=scan_id,
        create_response=create_response,
        start_response=start_response,
        stop_response=stop_response,
        results=results,
        delete_response=delete_response,
    )


def dump_result(result: E2EResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True)
