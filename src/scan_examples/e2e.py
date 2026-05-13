from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable

from .client import OpenVASAPIError, OpenVASScannerClient
from .feed import enrich_results

ProgressCallback = Callable[[str], None]
SCAN_COMPLETION_MODES = {"first-results", "scan-complete"}
RUNNING_SCAN_STATUSES = {"requested", "running", "stored"}
SUCCESS_SCAN_STATUSES = {"succeeded"}


@dataclass(slots=True)
class E2EResult:
    scan_id: str
    create_response: Any
    start_response: Any
    stop_response: Any
    final_status: dict[str, Any] | None
    results: list[dict[str, Any]]
    enriched_results: list[dict[str, Any]]
    findings_summary: dict[str, Any]
    delete_response: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "create_response": self.create_response,
            "start_response": self.start_response,
            "stop_response": self.stop_response,
            "final_status": self.final_status,
            "results": self.results,
            "enriched_results": self.enriched_results,
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


def _extract_status_phase(status: dict[str, Any] | None) -> str | None:
    if not status:
        return None
    value = status.get("status")
    return value.strip().lower() if isinstance(value, str) and value.strip() else None


def _status_is_running(status: dict[str, Any] | None) -> bool:
    phase = _extract_status_phase(status)
    return phase in RUNNING_SCAN_STATUSES


def _status_is_success(status: dict[str, Any] | None) -> bool:
    phase = _extract_status_phase(status)
    return phase in SUCCESS_SCAN_STATUSES


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
    results_timeout: float = 300.0,
    results_poll_interval: float = 15.0,
    completion_mode: str = "first-results",
    vt_index: dict[str, dict[str, Any]] | None = None,
    progress: ProgressCallback | None = None,
) -> E2EResult:
    wait_before_results = max(wait_before_results, 0)
    create_retry_delay = max(create_retry_delay, 0)
    results_timeout = max(results_timeout, 0)
    results_poll_interval = max(results_poll_interval, 0)
    if completion_mode not in SCAN_COMPLETION_MODES:
        raise ValueError(f"Unsupported completion mode {completion_mode!r}; expected one of {sorted(SCAN_COMPLETION_MODES)}")

    scan_id: str | None = None
    start_response: Any = None
    stop_response: Any = None
    delete_response: Any = None
    final_status: dict[str, Any] | None = None
    results: list[dict[str, Any]] = []
    findings_summary: dict[str, Any] = {"total": 0, "by_severity": {}, "by_type": {}}
    last_error: Exception | None = None
    findings_seen = False

    try:
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

        if wait_before_results > 0:
            _emit(progress, f"Initial wait {wait_before_results:g}s before polling for results")
            time.sleep(wait_before_results)

        deadline = time.monotonic() + results_timeout
        attempts = 0
        while True:
            attempts += 1
            _emit(progress, f"Fetching results for {scan_id} (poll {attempts})")
            results = client.get_results(scan_id)
            if results:
                if not findings_seen:
                    _emit(progress, f"Fetched {len(results)} findings")
                findings_seen = True

            if completion_mode == "scan-complete":
                final_status = client.get_scan_status(scan_id)
                phase = _extract_status_phase(final_status) or "unknown"
                _emit(progress, f"Scan {scan_id} status: {phase}")
                if not _status_is_running(final_status):
                    if not _status_is_success(final_status):
                        raise RuntimeError(f"Scan {scan_id} finished with status {phase}")
                    break
            elif results:
                final_status = client.get_scan_status(scan_id)
                break

            now = time.monotonic()
            if now >= deadline:
                wait_target = "scan completion" if completion_mode == "scan-complete" else "findings"
                raise RuntimeError(
                    f"Timed out after {results_timeout:g}s waiting for {wait_target} for scan {scan_id}"
                )
            if results and completion_mode == "scan-complete":
                _emit(progress, f"Scan still running after {len(results)} findings; waiting {results_poll_interval:g}s before retrying")
            else:
                _emit(progress, f"No findings yet; waiting {results_poll_interval:g}s before retrying")
            time.sleep(results_poll_interval)

        if not results:
            raise RuntimeError(f"Scan {scan_id} completed without findings")

        findings_summary = summarize_results(results)
        enriched_results = enrich_results(results, vt_index)

        if completion_mode == "first-results":
            _emit(progress, f"Stopping scan {scan_id}")
            stop_response = client.stop_scan(scan_id)
        else:
            stop_response = {"status": "not_stopped", "reason": "scan completed"}

        _emit(progress, f"Deleting scan {scan_id}")
        delete_response = client.delete_scan(scan_id)
        _emit(progress, f"Deleted scan {scan_id}")

        return E2EResult(
            scan_id=scan_id,
            create_response=create_response,
            start_response=start_response,
            stop_response=stop_response,
            final_status=final_status,
            results=results,
            enriched_results=enriched_results,
            findings_summary=findings_summary,
            delete_response=delete_response,
        )
    except Exception:
        if scan_id:
            if not findings_seen:
                _emit(progress, f"No findings before timeout; stopping scan {scan_id}")
            if stop_response is None:
                try:
                    _emit(progress, f"Stopping scan {scan_id}")
                    stop_response = client.stop_scan(scan_id)
                except Exception as exc:
                    _emit(progress, f"Best-effort stop failed for {scan_id}: {exc}")
            if delete_response is None:
                try:
                    _emit(progress, f"Deleting scan {scan_id}")
                    delete_response = client.delete_scan(scan_id)
                    _emit(progress, f"Deleted scan {scan_id}")
                except Exception as exc:
                    _emit(progress, f"Best-effort delete failed for {scan_id}: {exc}")
        raise


def dump_result(result: E2EResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True)
