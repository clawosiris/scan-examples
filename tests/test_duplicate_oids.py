from __future__ import annotations

import json

from scan_examples.duplicate_oids import find_duplicate_oids, render_duplicate_report
from scan_examples.feed import load_vt_metadata_entries


def test_load_vt_metadata_entries_returns_normalized_entries(tmp_path):
    metadata_path = tmp_path / "nasl"
    metadata_path.mkdir()
    vt_metadata = metadata_path / "vt-metadata.json"
    vt_metadata.write_text(
        json.dumps({"vt_metadata": [{"oid": "1.2.3", "name": "Example VT"}]}),
        encoding="utf-8",
    )

    resolved_path, entries = load_vt_metadata_entries(tmp_path)

    assert resolved_path == vt_metadata
    assert entries == [{"oid": "1.2.3", "name": "Example VT"}]


def test_find_duplicate_oids_reports_entry_context():
    duplicates = find_duplicate_oids(
        [
            {
                "oid": "1.2.3",
                "name": "First VT",
                "filename": "first.nasl",
                "references": [{"class": "cve", "id": "CVE-2026-0001"}],
            },
            {"oid": "4.5.6", "name": "Unique VT"},
            {
                "oid": "1.2.3",
                "name": "Second VT",
                "filename": "second.nasl",
                "tag": {"summary": "different body"},
            },
        ]
    )

    assert duplicates == [
        {
            "oid": "1.2.3",
            "occurrences": 2,
            "entries": [
                {
                    "index": 0,
                    "context": {
                        "oid": "1.2.3",
                        "name": "First VT",
                        "filename": "first.nasl",
                        "cves": ["CVE-2026-0001"],
                    },
                },
                {
                    "index": 2,
                    "context": {
                        "oid": "1.2.3",
                        "name": "Second VT",
                        "filename": "second.nasl",
                        "tag_summary": "different body",
                    },
                },
            ],
        }
    ]


def test_render_duplicate_report_includes_oid_and_indexes(tmp_path):
    metadata_path = tmp_path / "vt-metadata.json"
    report = render_duplicate_report(
        metadata_path,
        [
            {
                "oid": "1.2.3",
                "occurrences": 2,
                "entries": [
                    {"index": 3, "context": {"name": "First VT", "filename": "first.nasl"}},
                    {"index": 7, "context": {"name": "Second VT", "filename": "second.nasl"}},
                ],
            }
        ],
    )

    assert "OID 1.2.3 (2 occurrences)" in report
    assert "entry index: 3" in report
    assert "entry index: 7" in report
    assert "filename: first.nasl" in report
    assert "filename: second.nasl" in report
