from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable

from .client import OpenVASAPIError, OpenVASScannerClient

ProgressCallback = Callable[[str], None]


@dataclass(slots=True)
class E2EResult:
    scan_id: str
    create_response: Any
    start_response: Any
    stop_response: Any
    results: list[dict[str, Any]]
    findings_summary: dict[str, Any]
    delete_response: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "create_response": self.create_response,
            "start_response": self.start_response,
            "stop_response": self.stop_response,
            "results": self.results,
            "findings_summary": self.findings_summary,
            "delete_response": self.delete_response,
        }


def _emit(progress: ProgressCallback | None, message: str) -> None:
    if progress is not None:
        progress(message)


def _coerce_score(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _extract_severity_label(result: dict[str, Any]) -> str:
    for key in ("severity", "threat", "level"):
        value = result.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
        if isinstance(value, dict):
            for nested_key in ("label", "name", "value"):
                nested_value = value.get(nested_key)
                if isinstance(nested_value, str) and nested_value.strip():
                    return nested_value.strip().lower()
                score = _coerce_score(nested_value)
                if score is not None:
                    return _score_to_severity(score)

    for key in ("cvss", "cvss_base", "base_score", "severity_score"):
        score = _coerce_score(result.get(key))
        if score is not None:
            return _score_to_severity(score)

    return "unknown"


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    summary = {
        "total": len(results),
        "by_severity": {},
        "by_type": {},
    }
    for result in results:
        severity = _extract_severity_label(result)
        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

        result_type = result.get("type")
        if isinstance(result_type, str) and result_type.strip():
            type_label = result_type.strip().lower()
        else:
            type_label = "unknown"
        summary["by_type"][type_label] = summary["by_type"].get(type_label, 0) + 1
    return summary


def run_lifecycle(
    *,
    client: OpenVASScannerClient,
    payload: dict[str, Any],
    wait_before_results: float = 10.0,
    create_retries: int = 12,
    create_retry_delay: float = 10.0,
    progress: ProgressCallback | None = None,
) -> E2EResult:
    last_error: Exception | None = None
    for attempt in range(1, create_retries + 1):
        _emit(progress, f"Creating scan (attempt {attempt}/{create_retries})")
        try:
            scan_id = client.create_scan(payload)
            break
        except (OpenVASAPIError, OSError) as exc:
            last_error = exc
            if attempt == create_retries:
                raise
            _emit(progress, f"Create scan attempt {attempt} failed: {exc}")
            time.sleep(create_retry_delay)
    else:
        raise RuntimeError(f"Failed to create scan after {create_retries} attempts: {last_error}")

    create_response = {"id": scan_id}
    _emit(progress, f"Created scan {scan_id}")

    _emit(progress, f"Starting scan {scan_id}")
    start_response = client.start_scan(scan_id)

    _emit(progress, f"Waiting {wait_before_results:g}s before collecting results")
    time.sleep(wait_before_results)

    _emit(progress, f"Stopping scan {scan_id}")
    stop_response = client.stop_scan(scan_id)

    _emit(progress, f"Fetching results for {scan_id}")
    results = client.get_results(scan_id)
    findings_summary = summarize_results(results)
    _emit(progress, f"Fetched {findings_summary['total']} findings")

    _emit(progress, f"Deleting scan {scan_id}")
    delete_response = client.delete_scan(scan_id)
    _emit(progress, f"Deleted scan {scan_id}")

    return E2EResult(
        scan_id=scan_id,
        create_response=create_response,
        start_response=start_response,
        stop_response=stop_response,
        results=results,
        findings_summary=findings_summary,
        delete_response=delete_response,
    )


def dump_result(result: E2EResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True)
