from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .client import OpenVASAPIError


class PythonGvmUnavailableError(RuntimeError):
    """Raised when the optional python-gvm dependency is unavailable."""


def _load_openvasd_http_api() -> type:
    try:
        from gvm.protocols.http.openvasd import OpenvasdHttpAPIv1
    except ImportError as exc:  # pragma: no cover - exercised via tests with monkeypatching
        raise PythonGvmUnavailableError(
            "python-gvm backend requested, but the optional dependency is not installed. "
            "Install scan-examples with the 'python-gvm' extra to use this backend."
        ) from exc

    return OpenvasdHttpAPIv1


def _response_payload(response: Any) -> Any:
    if hasattr(response, "json"):
        return response.json()
    return response


@dataclass(slots=True)
class PythonGvmOpenvasdClient:
    base_url: str
    api: Any = field(init=False, repr=False)

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"Unsupported scanner base URL for python-gvm backend: {self.base_url!r}")
        if parsed.scheme == "https":
            raise ValueError(
                "The python-gvm backend in scan-examples currently supports plain HTTP endpoints only. "
                "Use the requests backend for HTTPS endpoints until mTLS flags are added here."
            )

        api_cls = _load_openvasd_http_api()
        port = parsed.port or 80
        self.api = api_cls(host_name=parsed.hostname, port=port)

    def create_scan(self, payload: dict[str, Any]) -> str:
        response = self.api.scans.create(
            payload["target"],
            payload["vts"],
            scan_preferences=payload.get("scan_preferences"),
        )
        data = _response_payload(response)
        if isinstance(data, str) and data:
            return data
        if isinstance(data, dict):
            for key in ("id", "scan_id", "scanId"):
                value = data.get(key)
                if isinstance(value, str) and value:
                    return value
        raise OpenVASAPIError(f"Create scan did not return a scan id: {data!r}")

    def start_scan(self, scan_id: str) -> dict[str, Any]:
        status_code = self.api.scans.start(scan_id)
        return {"status_code": status_code, "action": "start"}

    def stop_scan(self, scan_id: str) -> dict[str, Any]:
        status_code = self.api.scans.stop(scan_id)
        return {"status_code": status_code, "action": "stop"}

    def get_scan_status(self, scan_id: str) -> dict[str, Any]:
        data = _response_payload(self.api.scans.get_status(scan_id))
        if isinstance(data, dict):
            return data
        raise OpenVASAPIError(f"Unexpected scan status payload: {data!r}")

    def get_results(self, scan_id: str) -> list[dict[str, Any]]:
        data = _response_payload(self.api.scans.get_results(scan_id))
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            return data["results"]
        raise OpenVASAPIError(f"Unexpected results payload: {data!r}")

    def delete_scan(self, scan_id: str) -> dict[str, Any]:
        status_code = self.api.scans.delete(scan_id)
        return {"status_code": status_code, "deleted": True}
