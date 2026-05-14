from __future__ import annotations

"""End-to-end scan lifecycle helpers used by the example CLI and tests."""

import json
import time
from dataclasses import dataclass
from typing import Any, Callable

from .client import OpenVASAPIError, OpenVASScannerClient
from .enrichment import enrich_results

ProgressCallback = Callable[[str], None]
SCAN_COMPLETION_MODES = {"first-results", "scan-complete"}
RUNNING_SCAN_STATUSES = {"requested", "running", "stored"}
SUCCESS_SCAN_STATUSES = {"succeeded"}


@dataclass(slots=True)
class E2EResult:
    """Collected data from one end-to-end example run."""

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
        """Convert the dataclass into the JSON-friendly shape used by the CLI."""
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
    """Send a progress message when the caller asked for streaming updates."""
    if progress is not None:
        progress(message)


def _coerce_score(value: Any) -> float | None:
    """Parse a numeric severity score from strings or numeric values."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _score_to_severity(score: float) -> str:
    """Map a numeric score onto a coarse severity bucket."""
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
    """Derive a human-friendly severity label from varying result schemas."""
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
    """Extract the normalized status phase string from a status payload."""
    if not status:
        return None
    value = status.get("status")
    return value.strip().lower() if isinstance(value, str) and value.strip() else None


def _status_is_running(status: dict[str, Any] | None) -> bool:
    """Return ``True`` while the scanner still reports an active phase."""
    phase = _extract_status_phase(status)
    return phase in RUNNING_SCAN_STATUSES


def _status_is_success(status: dict[str, Any] | None) -> bool:
    """Return ``True`` when the scanner reported successful completion."""
    phase = _extract_status_phase(status)
    return phase in SUCCESS_SCAN_STATUSES


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a tiny aggregate summary grouped by severity and finding type."""
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
    no_findings_increment_timeout: float = 0.0,
    completion_mode: str = "first-results",
    min_results: int = 1,
    vt_index: dict[str, dict[str, Any]] | None = None,
    scap_cve_index: dict[str, dict[str, Any]] | None = None,
    progress: ProgressCallback | None = None,
) -> E2EResult:
    """Run the full scan lifecycle used by the example CLI.

    The function is intentionally verbose so humans can follow the sequence:
    create, start, poll, enrich, stop if needed, and finally delete.
    """
    wait_before_results = max(wait_before_results, 0)
    create_retry_delay = max(create_retry_delay, 0)
    results_timeout = max(results_timeout, 0)
    results_poll_interval = max(results_poll_interval, 0)
    no_findings_increment_timeout = max(no_findings_increment_timeout, 0)
    min_results = max(int(min_results), 1)
    if completion_mode not in SCAN_COMPLETION_MODES:
        expected_modes = sorted(SCAN_COMPLETION_MODES)
        raise ValueError(
            f"Unsupported completion mode {completion_mode!r}; expected one of {expected_modes}"
        )

    scan_id: str | None = None
    start_response: Any = None
    stop_response: Any = None
    delete_response: Any = None
    final_status: dict[str, Any] | None = None
    results: list[dict[str, Any]] = []
    findings_summary: dict[str, Any] = {"total": 0, "by_severity": {}, "by_type": {}}
    last_error: Exception | None = None
    findings_seen = False
    last_findings_count = 0
    last_findings_increment_at: float | None = None
    completion_reason = "scan_completed"

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

        start_polling_at = time.monotonic()
        deadline = start_polling_at + results_timeout
        last_findings_increment_at = start_polling_at
        attempts = 0
        while True:
            attempts += 1
            # Polling continues until we either hit the requested completion
            # condition or run out of patience and time out.
            _emit(progress, f"Fetching results for {scan_id} (poll {attempts})")
            results = client.get_results(scan_id)
            now = time.monotonic()
            findings_count = len(results)
            if findings_count > last_findings_count:
                _emit(progress, f"Findings increased from {last_findings_count} to {findings_count}")
                last_findings_count = findings_count
                last_findings_increment_at = now
            if results:
                if not findings_seen:
                    _emit(progress, f"Fetched {len(results)} findings")
                findings_seen = True

            if completion_mode == "scan-complete":
                # In full completion mode we trust the scanner status endpoint,
                # not just the presence of findings, because results can appear
                # before the scan has naturally finished.
                final_status = client.get_scan_status(scan_id)
                phase = _extract_status_phase(final_status) or "unknown"
                _emit(progress, f"Scan {scan_id} status: {phase}")
                if not _status_is_running(final_status):
                    if not _status_is_success(final_status):
                        raise RuntimeError(f"Scan {scan_id} finished with status {phase}")
                    completion_reason = "scan_completed"
                    break
                if (
                    no_findings_increment_timeout > 0
                    and last_findings_increment_at is not None
                    and now - last_findings_increment_at >= no_findings_increment_timeout
                ):
                    completion_reason = "findings_stalled"
                    _emit(
                        progress,
                        f"No increase in findings for {no_findings_increment_timeout:g}s; stopping scan {scan_id}",
                    )
                    break
            elif findings_count >= min_results:
                final_status = client.get_scan_status(scan_id)
                break

            if now >= deadline:
                wait_target = "scan completion" if completion_mode == "scan-complete" else "findings"
                raise RuntimeError(
                    f"Timed out after {results_timeout:g}s waiting for {wait_target} for scan {scan_id}"
                )
            if results and completion_mode == "scan-complete":
                _emit(
                    progress,
                    f"Scan still running after {len(results)} findings; "
                    f"waiting {results_poll_interval:g}s before retrying",
                )
            elif results:
                _emit(
                    progress,
                    f"Fetched {len(results)} findings; waiting for at least {min_results} "
                    f"before retrying in {results_poll_interval:g}s",
                )
            else:
                _emit(progress, f"No findings yet; waiting {results_poll_interval:g}s before retrying")
            time.sleep(results_poll_interval)

        if not results:
            raise RuntimeError(f"Scan {scan_id} completed without findings")

        findings_summary = summarize_results(results)
        enriched_results = enrich_results(results, vt_index, scap_cve_index)

        if completion_mode == "first-results":
            _emit(progress, f"Stopping scan {scan_id}")
            stop_response = client.stop_scan(scan_id)
        else:
            if completion_reason == "findings_stalled":
                _emit(progress, f"Stopping scan {scan_id}")
                stop_response = client.stop_scan(scan_id)
                if isinstance(stop_response, dict):
                    stop_response = {**stop_response, "reason": "findings_stalled"}
            else:
                stop_response = {"status": "not_stopped", "reason": "scan_completed"}

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
            # Best-effort cleanup matters here because this example is often run
            # repeatedly in CI or local labs where orphaned scans become noise.
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
    """Render an :class:`E2EResult` as stable, readable JSON."""
    return json.dumps(result.to_dict(), indent=2, sort_keys=True)
