from __future__ import annotations

import json

from scan_examples.feed import (
    dump_pretty_enriched_results,
    enrich_results,
    extract_result_oid,
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

    assert enriched[0]["vt_metadata_status"] == "matched"
    assert enriched[0]["vt_metadata"]["name"] == "Example VT"
    assert enriched[1]["vt_metadata_status"] == "not_found"
    assert enriched[1]["vt_metadata"] is None
    assert enriched[2]["vt_metadata_status"] == "missing_oid"
    assert enriched[2]["vt_metadata"] is None


def test_enrich_results_handles_unavailable_metadata_index():
    enriched = enrich_results([{"id": 1, "oid": "1.2.3"}], None)

    assert enriched == [
        {
            "result": {"id": 1, "oid": "1.2.3"},
            "vt_metadata_status": "metadata_unavailable",
            "vt_metadata": None,
        }
    ]


def test_dump_pretty_enriched_results_is_human_readable():
    rendered = dump_pretty_enriched_results([
        {"result": {"id": 1, "oid": "1.2.3"}, "vt_metadata_status": "not_found", "vt_metadata": None}
    ])

    assert '"vt_metadata_status": "not_found"' in rendered
    assert rendered.startswith("[")
