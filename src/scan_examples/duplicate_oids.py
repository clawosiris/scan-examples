from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .feed import load_vt_metadata_entries


def _summarize_entry(entry: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key in ("oid", "name", "filename", "family", "category"):
        value = entry.get(key)
        if value is not None:
            summary[key] = value

    references = entry.get("references")
    if isinstance(references, list):
        cves = []
        for reference in references:
            if not isinstance(reference, dict):
                continue
            ref_id = reference.get("id")
            if isinstance(ref_id, str) and ref_id.upper().startswith("CVE-"):
                cves.append(ref_id.upper())
        if cves:
            summary["cves"] = sorted(set(cves))

    tag = entry.get("tag")
    if isinstance(tag, dict):
        for key in ("summary", "solution", "insight"):
            value = tag.get(key)
            if isinstance(value, str) and value.strip():
                summary[f"tag_{key}"] = value.strip()
    return summary


def find_duplicate_oids(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_oid: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for index, entry in enumerate(entries):
        oid = entry.get("oid")
        if isinstance(oid, str) and oid:
            by_oid[oid].append({"index": index, "entry": entry})

    duplicates: list[dict[str, Any]] = []
    for oid, matches in sorted(by_oid.items()):
        if len(matches) < 2:
            continue
        duplicates.append(
            {
                "oid": oid,
                "occurrences": len(matches),
                "entries": [
                    {
                        "index": match["index"],
                        "context": _summarize_entry(match["entry"]),
                    }
                    for match in matches
                ],
            }
        )
    return duplicates


def render_duplicate_report(metadata_path: Path, duplicates: list[dict[str, Any]]) -> str:
    if not duplicates:
        return f"No duplicate OIDs found in {metadata_path}"

    lines = [f"Found {len(duplicates)} duplicate OID group(s) in {metadata_path}"]
    for duplicate in duplicates:
        lines.append("")
        lines.append(f"OID {duplicate['oid']} ({duplicate['occurrences']} occurrences)")
        for entry in duplicate["entries"]:
            context = entry["context"]
            lines.append(f"  - entry index: {entry['index']}")
            for key in ("name", "filename", "family", "category"):
                value = context.get(key)
                if value is not None:
                    lines.append(f"    {key}: {value}")
            cves = context.get("cves")
            if cves:
                lines.append(f"    cves: {', '.join(cves)}")
            for key in ("tag_summary", "tag_solution", "tag_insight"):
                value = context.get(key)
                if value is not None:
                    lines.append(f"    {key}: {value}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect vt-metadata feed data for duplicate OIDs and print their context"
    )
    parser.add_argument(
        "--vt-metadata",
        required=True,
        help="Path to vt-metadata.json or a directory containing it",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit duplicate groups as JSON instead of text",
    )
    parser.add_argument("--output", help="Write the report to a file")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    metadata_path, entries = load_vt_metadata_entries(args.vt_metadata)
    duplicates = find_duplicate_oids(entries)
    rendered = (
        json.dumps({"vt_metadata_path": str(metadata_path), "duplicates": duplicates}, indent=2)
        if args.json
        else render_duplicate_report(metadata_path, duplicates)
    )
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 1 if duplicates else 0


if __name__ == "__main__":
    raise SystemExit(main())
