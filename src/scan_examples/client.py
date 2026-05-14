"""HTTP client helpers for the OpenVAS scanner REST API example."""

from dataclasses import dataclass, field
from typing import Any

import requests


class OpenVASAPIError(RuntimeError):
    """Raised when the scanner API returns an error response."""


@dataclass(slots=True)
class OpenVASScannerClient:
    """Small convenience wrapper around the scanner REST API.

    The example keeps this client intentionally lightweight: it only knows how
    to call the endpoints used by the demo workflows and how to normalize a few
    response shape differences.
    """

    base_url: str
    timeout: float = 30.0
    verify_tls: bool = True
    session: requests.Session = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Normalize configuration and create the shared HTTP session."""
        self.base_url = self.base_url.rstrip("/")
        self.session = requests.Session()

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Execute one API request and decode the response body.

        The scanner may respond with JSON or plain text depending on the
        endpoint, so we try JSON first and fall back to text when needed.
        """
        response = self.session.request(
            method,
            f"{self.base_url}{path}",
            timeout=self.timeout,
            verify=self.verify_tls,
            **kwargs,
        )
        if response.status_code >= 400:
            raise OpenVASAPIError(
                f"{method} {path} failed with {response.status_code}: {response.text.strip()}"
            )
        if not response.content:
            return None
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            return response.json()
        try:
            return response.json()
        except ValueError:
            return response.text

    def create_scan(self, payload: dict[str, Any]) -> str:
        """Create a scan and return its identifier.

        Different scanner builds may return the new scan id either as a raw
        string or inside a small JSON object, so this method accepts both.
        """
        data = self._request("POST", "/scans", json=payload)
        if isinstance(data, str) and data:
            return data
        if isinstance(data, dict):
            for key in ("id", "scan_id", "scanId"):
                value = data.get(key)
                if isinstance(value, str) and value:
                    return value
        raise OpenVASAPIError(f"Create scan did not return a scan id: {data!r}")

    def scan_action(self, scan_id: str, action: str) -> Any:
        """Send a lifecycle action such as ``start`` or ``stop``."""
        return self._request("POST", f"/scans/{scan_id}", json={"action": action})

    def start_scan(self, scan_id: str) -> Any:
        """Start a previously created scan."""
        return self.scan_action(scan_id, "start")

    def stop_scan(self, scan_id: str) -> Any:
        """Stop a running scan."""
        return self.scan_action(scan_id, "stop")

    def get_scan_status(self, scan_id: str) -> dict[str, Any]:
        """Fetch the current status document for a scan."""
        data = self._request("GET", f"/scans/{scan_id}/status")
        if isinstance(data, dict):
            return data
        raise OpenVASAPIError(f"Unexpected scan status payload: {data!r}")

    def get_results(self, scan_id: str) -> list[dict[str, Any]]:
        """Fetch result items for a scan.

        Some endpoints return the results as a top-level array while others wrap
        them in ``{"results": [...]}``, so we normalize both into a list.
        """
        data = self._request("GET", f"/scans/{scan_id}/results")
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            return data["results"]
        raise OpenVASAPIError(f"Unexpected results payload: {data!r}")

    def delete_scan(self, scan_id: str) -> Any:
        """Delete a scan and return the raw API response."""
        return self._request("DELETE", f"/scans/{scan_id}")
