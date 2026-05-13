from __future__ import annotations

import json

from scan_examples.feed import (
    dump_pretty_enriched_results,
    enrich_results,
    extract_result_oid,
    load_scap_cve_index,
    load_vt_metadata_index,
    resolve_vt_metadata_path,
)


def test_resolve_vt_metadata_path_supports_root_file(tmp_path):
    metadata_path = tmp_path / "vt-metadata.json"
    metadata_path.write_text("[]", encoding="utf-8")

    assert resolve_vt_metadata_path(tmp_path) == metadata_path


def test_load_vt_metadata_index_indexes_entries_by_oid(tmp_path):
    metadata_path = tmp_path / "nasl"
    metadata_path.mkdir()
    vt_metadata = metadata_path / "vt-metadata.json"
    vt_metadata.write_text(
        json.dumps([
            {"oid": "1.2.3", "name": "Example VT"},
            {"oid": "4.5.6", "name": "Other VT"},
        ]),
        encoding="utf-8",
    )

    resolved_path, vt_index = load_vt_metadata_index(tmp_path)

    assert resolved_path == vt_metadata
    assert vt_index["1.2.3"]["name"] == "Example VT"
    assert vt_index["4.5.6"]["name"] == "Other VT"


def test_extract_result_oid_supports_nested_nvt_oid():
    result = {"nvt": {"oid": "1.3.6.1"}}

    assert extract_result_oid(result) == "1.3.6.1"


def test_enrich_results_marks_missing_metadata_states():
    results = [
        {"id": 1, "oid": "1.2.3", "type": "alarm"},
        {"id": 2, "oid": "9.9.9", "type": "alarm"},
        {"id": 3, "type": "log"},
    ]
    vt_index = {
        "1.2.3": {
            "oid": "1.2.3",
            "name": "Example VT",
            "filename": "example.nasl",
            "family": "General",
            "category": "gather_info",
            "references": [{"class": "cve", "id": "CVE-2026-0001"}],
            "tag": {"summary": "Example summary"},
        }
    }

    enriched = enrich_results(results, vt_index)

    assert enriched[0]["vt-metadata-status"] == "matched"
    assert enriched[0]["vt-metadata"]["name"] == "Example VT"
    assert enriched[1]["vt-metadata-status"] == "not_found"
    assert enriched[1]["vt-metadata"] is None
    assert enriched[2]["vt-metadata-status"] == "missing_oid"
    assert enriched[2]["vt-metadata"] is None


def test_enrich_results_preserves_raw_result_shape_and_adds_metadata_fields():
    raw_result = {
        "id": 3,
        "type": "alarm",
        "ip_address": "127.0.0.1",
        "hostname": "localhost",
        "oid": "1.3.6.1.4.1.25623.1.0.147696",
        "protocol": "tcp",
        "message": "Installed version: 9.53.3\nFixed version: 9.55",
    }
    vt_index = {
        "1.3.6.1.4.1.25623.1.0.147696": {
            "oid": "1.3.6.1.4.1.25623.1.0.147696",
            "name": "Ghostscript 9.50 < 9.55.0 Sandbox Escape Vulnerability - Linux",
            "filename": "2022/artifex/gb_ghostscript_sandbox_escape_vuln_sep21_lin.nasl",
            "family": "General",
            "category": "gather_info",
            "references": [{"class": "cve", "id": "CVE-2021-3781"}],
            "tag": {"solution": "Update to version 9.55 or later."},
        }
    }

    enriched = enrich_results([raw_result], vt_index)

    assert enriched[0]["id"] == raw_result["id"]
    assert enriched[0]["message"] == raw_result["message"]
    assert "result" not in enriched[0]
    assert enriched[0]["vt-metadata"]["name"] == "Ghostscript 9.50 < 9.55.0 Sandbox Escape Vulnerability - Linux"
    assert enriched[0]["vt-metadata-status"] == "matched"



def test_enrich_results_handles_unavailable_metadata_index():
    enriched = enrich_results([{"id": 1, "oid": "1.2.3"}], None)

    assert enriched == [
        {
            "id": 1,
            "oid": "1.2.3",
            "vt-metadata-status": "metadata_unavailable",
            "vt-metadata": None,
            "cve-ids": [],
            "cve-metadata-status": "no_cves",
            "cve-metadata": [],
        }
    ]


def test_load_scap_cve_index_supports_nvd_2_payload(tmp_path):
    scap_path = tmp_path / "scap"
    scap_path.mkdir()
    (scap_path / "nvdcve-2.0-test.json").write_text(
        json.dumps({
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-0001",
                        "sourceIdentifier": "nvd@example",
                        "published": "2026-01-01T00:00:00.000",
                        "lastModified": "2026-01-02T00:00:00.000",
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": "Example CVE"}],
                        "references": {"referenceData": [{"url": "https://example.test/advisory"}]},
                        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "source": "nvd@example",
                                    "type": "Primary",
                                    "cvssData": {
                                        "version": "3.1",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                    },
                                }
                            ]
                        },
                        "configurations": [
                            {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:example:app:1.0:*:*:*:*:*:*:*"}]}]}
                        ],
                    }
                }
            ]
        }),
        encoding="utf-8",
    )

    paths, cve_index = load_scap_cve_index(scap_path)

    assert paths == [scap_path / "nvdcve-2.0-test.json"]
    cve = cve_index["CVE-2026-0001"]
    assert cve["descriptions"] == ["Example CVE"]
    assert cve["references"] == ["https://example.test/advisory"]
    assert cve["weaknesses"] == ["CWE-79"]
    assert cve["metrics"]["cvssMetricV31"]["cvssData"]["baseScore"] == 9.8
    assert cve["affected_cpes"] == ["cpe:2.3:a:example:app:1.0:*:*:*:*:*:*:*"]


def test_load_scap_cve_index_normalizes_and_filters_cve_ids(tmp_path):
    scap_path = tmp_path / "scap.json"
    scap_path.write_text(
        json.dumps([
            {"id": "cve-2026-0002", "descriptions": [{"lang": "en", "value": "lowercase CVE"}]},
            {"id": "NOT-A-CVE", "descriptions": [{"lang": "en", "value": "ignore me"}]},
        ]),
        encoding="utf-8",
    )

    _paths, cve_index = load_scap_cve_index(scap_path)

    assert list(cve_index) == ["CVE-2026-0002"]
    assert cve_index["CVE-2026-0002"]["descriptions"] == ["lowercase CVE"]


def test_enrich_results_adds_cve_metadata_after_vt_oid_match():
    results = [{"id": 1, "oid": "1.2.3", "type": "alarm"}]
    vt_index = {
        "1.2.3": {
            "oid": "1.2.3",
            "name": "Example VT",
            "references": [{"class": "cve", "id": "CVE-2026-0001"}],
        }
    }
    cve_index = {"CVE-2026-0001": {"id": "CVE-2026-0001", "descriptions": ["Example CVE"]}}

    enriched = enrich_results(results, vt_index, cve_index)

    assert enriched[0]["vt-metadata-status"] == "matched"
    assert enriched[0]["cve-ids"] == ["CVE-2026-0001"]
    assert enriched[0]["cve-metadata-status"] == "matched"
    assert enriched[0]["cve-metadata"] == [{"id": "CVE-2026-0001", "descriptions": ["Example CVE"]}]


def test_enrich_results_reports_missing_cve_metadata():
    results = [{"id": 1, "oid": "1.2.3", "type": "alarm"}]
    vt_index = {"1.2.3": {"oid": "1.2.3", "references": [{"class": "cve", "id": "CVE-2026-0002"}]}}

    enriched = enrich_results(results, vt_index, {})

    assert enriched[0]["cve-ids"] == ["CVE-2026-0002"]
    assert enriched[0]["cve-metadata-status"] == "not_found"
    assert enriched[0]["cve-metadata"] == []


def test_dump_pretty_enriched_results_preserves_enriched_result_shape_for_logs():
    rendered = dump_pretty_enriched_results([
        {
            "id": 1,
            "oid": "1.2.3",
            "vt-metadata-status": "matched",
            "vt-metadata": {"name": "Example VT"},
            "cve-ids": ["CVE-2026-0001"],
            "cve-metadata-status": "matched",
            "cve-metadata": [{"id": "CVE-2026-0001", "descriptions": ["Example CVE"]}],
        }
    ])
    payload = json.loads(rendered)

    assert payload[0]["id"] == 1
    assert payload[0]["oid"] == "1.2.3"
    assert payload[0]["vt-metadata"] == {"name": "Example VT"}
    assert payload[0]["cve-ids"] == ["CVE-2026-0001"]
    assert payload[0]["cve-metadata"] == [{"id": "CVE-2026-0001", "descriptions": ["Example CVE"]}]
    assert rendered.startswith("[")
