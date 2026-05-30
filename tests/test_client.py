import json
from types import SimpleNamespace

import pytest

from scan_examples.client import OpenVASAPIError, OpenVASScannerClient


class DummySession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def request(self, method, url, timeout, verify, **kwargs):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "timeout": timeout,
                "verify": verify,
                **kwargs,
            }
        )
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


def test_create_scan_accepts_raw_string_id():
    client = OpenVASScannerClient("http://scanner")
    client.session = DummySession([make_response(payload="scan-123")])

    assert client.create_scan({"target": {}, "vts": []}) == "scan-123"


def test_get_results_accepts_wrapped_results():
    client = OpenVASScannerClient("http://scanner")
    client.session = DummySession([make_response(payload={"results": [{"id": 1}]})])

    assert client.get_results("scan-123") == [{"id": 1}]


def test_get_results_follows_openvasd_result_pages():
    client = OpenVASScannerClient("http://scanner")
    client.session = DummySession(
        [
            make_response(
                payload={
                    "results": [{"id": 1}, {"id": 2}],
                    "offset": 0,
                    "limit": 2,
                    "total": 5,
                    "next_offset": 2,
                }
            ),
            make_response(
                payload={
                    "results": [{"id": 3}, {"id": 4}],
                    "offset": 2,
                    "limit": 2,
                    "total": 5,
                    "next_offset": 4,
                }
            ),
            make_response(
                payload={
                    "results": [{"id": 5}],
                    "offset": 4,
                    "limit": 2,
                    "total": 5,
                    "next_offset": None,
                }
            ),
        ]
    )

    assert client.get_results("scan-123") == [
        {"id": 1},
        {"id": 2},
        {"id": 3},
        {"id": 4},
        {"id": 5},
    ]
    assert client.session.calls[1]["params"] == {"offset": 2, "limit": 2}
    assert client.session.calls[2]["params"] == {"offset": 4, "limit": 2}


def test_get_scan_status_returns_status_payload():
    client = OpenVASScannerClient("http://scanner")
    client.session = DummySession([make_response(payload={"status": "succeeded"})])

    assert client.get_scan_status("scan-123") == {"status": "succeeded"}


def test_error_response_raises():
    client = OpenVASScannerClient("http://scanner")
    client.session = DummySession(
        [make_response(status_code=500, payload={"error": "boom"})]
    )

    with pytest.raises(OpenVASAPIError):
        client.get_results("scan-123")
