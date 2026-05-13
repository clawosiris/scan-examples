from __future__ import annotations

from types import SimpleNamespace

import pytest

from scan_examples.client import OpenVASAPIError
from scan_examples.python_gvm_client import PythonGvmOpenvasdClient, PythonGvmUnavailableError


class DummyResponse(SimpleNamespace):
    def json(self):
        return self.payload


class DummyScansAPI:
    def __init__(self):
        self.calls = []

    def create(self, target, vts, *, scan_preferences=None):
        self.calls.append(("create", target, vts, scan_preferences))
        return DummyResponse(payload={"id": "scan-123"})

    def start(self, scan_id):
        self.calls.append(("start", scan_id))
        return 200

    def stop(self, scan_id):
        self.calls.append(("stop", scan_id))
        return 200

    def get_status(self, scan_id):
        self.calls.append(("status", scan_id))
        return DummyResponse(payload={"status": "succeeded"})

    def get_results(self, scan_id):
        self.calls.append(("results", scan_id))
        return DummyResponse(payload={"results": [{"id": 1}]})

    def delete(self, scan_id):
        self.calls.append(("delete", scan_id))
        return 204


class DummyOpenvasdHttpAPIv1:
    def __init__(self, *, host_name, port):
        self.host_name = host_name
        self.port = port
        self.scans = DummyScansAPI()


def test_python_gvm_client_uses_openvasd_http_api(monkeypatch):
    monkeypatch.setattr(
        "scan_examples.python_gvm_client._load_openvasd_http_api",
        lambda: DummyOpenvasdHttpAPIv1,
    )

    client = PythonGvmOpenvasdClient("http://openvasd:80")

    scan_id = client.create_scan({"target": {"hosts": ["target"]}, "vts": [{"oid": "1.2.3"}]})

    assert scan_id == "scan-123"
    assert client.start_scan(scan_id) == {"status_code": 200, "action": "start"}
    assert client.get_scan_status(scan_id) == {"status": "succeeded"}
    assert client.get_results(scan_id) == [{"id": 1}]
    assert client.delete_scan(scan_id) == {"status_code": 204, "deleted": True}
    assert client.api.host_name == "openvasd"
    assert client.api.port == 80


def test_python_gvm_client_rejects_https_without_mtls(monkeypatch):
    monkeypatch.setattr(
        "scan_examples.python_gvm_client._load_openvasd_http_api",
        lambda: DummyOpenvasdHttpAPIv1,
    )

    with pytest.raises(ValueError, match="plain HTTP endpoints only"):
        PythonGvmOpenvasdClient("https://openvasd.example:443")


def test_python_gvm_client_surfaces_missing_dependency(monkeypatch):
    monkeypatch.setattr(
        "scan_examples.python_gvm_client._load_openvasd_http_api",
        lambda: (_ for _ in ()).throw(PythonGvmUnavailableError("missing")),
    )

    with pytest.raises(PythonGvmUnavailableError, match="missing"):
        PythonGvmOpenvasdClient("http://openvasd:80")


def test_python_gvm_client_rejects_invalid_create_payload(monkeypatch):
    class BadScansAPI(DummyScansAPI):
        def create(self, target, vts, *, scan_preferences=None):
            return DummyResponse(payload={"unexpected": True})

    class BadOpenvasdHttpAPIv1(DummyOpenvasdHttpAPIv1):
        def __init__(self, *, host_name, port):
            self.host_name = host_name
            self.port = port
            self.scans = BadScansAPI()

    monkeypatch.setattr(
        "scan_examples.python_gvm_client._load_openvasd_http_api",
        lambda: BadOpenvasdHttpAPIv1,
    )

    client = PythonGvmOpenvasdClient("http://openvasd:80")

    with pytest.raises(OpenVASAPIError, match="Create scan did not return a scan id"):
        client.create_scan({"target": {"hosts": ["target"]}, "vts": [{"oid": "1.2.3"}]})
