from __future__ import annotations

import json

from scan_examples.enrichment import enrich_results_from_files, load_scan_results, main


def test_load_scan_results_accepts_raw_result_list(tmp_path):
    results_path = tmp_path / "results.json"
    results_path.write_text(json.dumps([{"id": 1, "oid": "1.2.3"}]), encoding="utf-8")

    assert load_scan_results(results_path) == [{"id": 1, "oid": "1.2.3"}]


def test_load_scan_results_accepts_scanner_result_payload(tmp_path):
    results_path = tmp_path / "results.json"
    results_path.write_text(
        json.dumps({"scan_id": "scan-123", "results": [{"id": 1, "oid": "1.2.3"}]}),
        encoding="utf-8",
    )

    assert load_scan_results(results_path) == [{"id": 1, "oid": "1.2.3"}]


def test_enrich_results_from_files_requires_vt_metadata_and_uses_optional_scap(tmp_path):
    results_path = tmp_path / "results.json"
    vt_metadata_path = tmp_path / "vt-metadata.json"
    scap_path = tmp_path / "scap.json"
    results_path.write_text(json.dumps([{"id": 1, "oid": "1.2.3"}]), encoding="utf-8")
    vt_metadata_path.write_text(
        json.dumps([
            {
                "oid": "1.2.3",
                "name": "Example VT",
                "references": [{"class": "cve", "id": "CVE-2026-0001"}],
            }
        ]),
        encoding="utf-8",
    )
    scap_path.write_text(
        json.dumps([
            {"id": "CVE-2026-0001", "descriptions": [{"lang": "en", "value": "Example CVE"}]}
        ]),
        encoding="utf-8",
    )

    enriched = enrich_results_from_files(
        results_path=results_path,
        vt_metadata_path=vt_metadata_path,
        scap_path=scap_path,
    )

    assert enriched[0]["id"] == 1
    assert enriched[0]["feed-metadata-source"] == "vt"
    assert enriched[0]["vt-metadata-status"] == "matched"
    assert enriched[0]["vt-metadata"]["name"] == "Example VT"
    assert enriched[0]["notus-metadata"] == []
    assert enriched[0]["cve-metadata-status"] == "matched"
    assert enriched[0]["cve-metadata"][0]["descriptions"] == ["Example CVE"]


def test_enrich_results_from_files_supports_notus_only_enrichment(tmp_path):
    results_path = tmp_path / "results.json"
    notus_dir = tmp_path / "advisories"
    notus_dir.mkdir()
    (notus_dir / "example_os.notus").write_text(
        json.dumps(
            {
                "version": "1.0",
                "package_type": "rpm",
                "product_name": "Example OS",
                "advisories": [
                    {
                        "oid": "9.9.9",
                        "fixed_packages": [{"full_name": "pkg-2.0-1.x86_64"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    results_path.write_text(json.dumps([{"id": 1, "oid": "9.9.9"}]), encoding="utf-8")

    enriched = enrich_results_from_files(
        results_path=results_path,
        notus_path=notus_dir,
    )

    assert enriched[0]["feed-metadata-source"] == "notus"
    assert enriched[0]["notus-metadata-status"] == "matched"
    assert enriched[0]["notus-metadata"][0]["product_name"] == "Example OS"



def test_standalone_enrichment_cli_writes_json_output(tmp_path):
    results_path = tmp_path / "results.json"
    vt_metadata_path = tmp_path / "vt-metadata.json"
    output_path = tmp_path / "enriched.json"
    results_path.write_text(
        json.dumps({"results": [{"id": 1, "oid": "1.2.3"}]}),
        encoding="utf-8",
    )
    vt_metadata_path.write_text(
        json.dumps([{"oid": "1.2.3", "name": "Example VT"}]),
        encoding="utf-8",
    )

    assert main([
        "--results",
        str(results_path),
        "--vt-metadata",
        str(vt_metadata_path),
        "--output",
        str(output_path),
    ]) == 0

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload[0]["id"] == 1
    assert payload[0]["feed-metadata-source"] == "vt"
    assert payload[0]["vt-metadata"]["name"] == "Example VT"
