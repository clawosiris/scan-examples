from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from scan_examples.client import OpenVASAPIError, OpenVASScannerClient


class DummySession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def request(self, method, url, timeout, verify, **kwargs):
        self.calls.append({"method": method, "url": url, "timeout": timeout, "verify": verify, **kwargs})
        return self._responses.pop(0)


class DummyResponse(SimpleNamespace):
    def json(self):
        return json.loads(self.text)


def make_response(status_code=200, payload=None, content_type="application/json"):
    text = json.dumps(payload) if payload is not None else ""
    return DummyResponse(
        status_code=status_code,
        text=text,
        content=text.encode() if text else b"",
        headers={"content-type": content_type},
    )


def test_create_scan_returns_id():
    client = OpenVASScannerClient("http://scanner")
    client.session = DummySession([make_response(payload={"id": "scan-123"})])

    assert client.create_scan({"target": {}, "vts": []}) == "scan-123"


def test_get_results_accepts_wrapped_results():
    client = OpenVASScannerClient("http://scanner")
    client.session = DummySession([make_response(payload={"results": [{"id": 1}]})])

    assert client.get_results("scan-123") == [{"id": 1}]


def test_error_response_raises():
    client = OpenVASScannerClient("http://scanner")
    client.session = DummySession([make_response(status_code=500, payload={"error": "boom"})])

    with pytest.raises(OpenVASAPIError):
        client.get_results("scan-123")
