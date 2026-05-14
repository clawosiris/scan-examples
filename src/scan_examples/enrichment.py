"""Result enrichment helpers for correlating findings with local feed metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .feed import load_scap_cve_index, load_vt_metadata_index


def select_vt_metadata_fields(entry: dict[str, Any]) -> dict[str, Any]:
    """Keep the VT metadata fields that are most useful in enriched output."""
    selected: dict[str, Any] = {}
    for key in (
        "oid",
        "name",
        "filename",
        "family",
        "category",
        "references",
        "dependencies",
        "required_ports",
        "required_udp_ports",
        "tag",
    ):
        if key in entry:
            selected[key] = entry[key]
    return selected


def extract_cve_ids_from_vt_metadata(entry: dict[str, Any] | None) -> list[str]:
    """Extract unique CVE identifiers from a VT metadata entry."""
    if not entry:
        return []
    cve_ids: list[str] = []
    references = entry.get("references")
    if isinstance(references, list):
        for reference in references:
            if not isinstance(reference, dict):
                continue
            ref_class = reference.get("class")
            ref_id = reference.get("id")
            if (
                isinstance(ref_id, str)
                and ref_id.upper().startswith("CVE-")
                and (ref_class is None or str(ref_class).lower() == "cve")
            ):
                cve_ids.append(ref_id.upper())
    return sorted(set(cve_ids))


def extract_result_oid(result: dict[str, Any]) -> str | None:
    """Return the VT OID from either the top-level result or nested NVT data."""
    oid = result.get("oid")
    if isinstance(oid, str) and oid:
        return oid

    nvt = result.get("nvt")
    if isinstance(nvt, dict):
        nested_oid = nvt.get("oid")
        if isinstance(nested_oid, str) and nested_oid:
            return nested_oid

    return None


def _enriched_result(
    result: dict[str, Any],
    *,
    vt_metadata_status: str,
    vt_metadata: dict[str, Any] | None,
    cve_ids: list[str] | None = None,
    cve_metadata_status: str = "no_cves",
    cve_metadata: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the normalized output object for one scanner finding."""
    return {
        **result,
        "vt-metadata-status": vt_metadata_status,
        "vt-metadata": vt_metadata,
        "cve-ids": cve_ids or [],
        "cve-metadata-status": cve_metadata_status,
        "cve-metadata": cve_metadata or [],
    }


def enrich_results(
    results: list[dict[str, Any]],
    vt_index: dict[str, dict[str, Any]] | None,
    scap_cve_index: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Attach VT metadata and optional CVE metadata to scanner results."""
    enriched: list[dict[str, Any]] = []
    for result in results:
        oid = extract_result_oid(result)
        if oid is None:
            enriched.append(
                _enriched_result(result, vt_metadata_status="missing_oid", vt_metadata=None)
            )
            continue

        if vt_index is None:
            enriched.append(
                _enriched_result(
                    result,
                    vt_metadata_status="metadata_unavailable",
                    vt_metadata=None,
                )
            )
            continue

        entry = vt_index.get(oid)
        if entry is None:
            enriched.append(
                _enriched_result(result, vt_metadata_status="not_found", vt_metadata=None)
            )
            continue

        cve_ids = extract_cve_ids_from_vt_metadata(entry)
        # VT metadata gives us the CVE ids; the optional SCAP index lets us
        # expand those ids into richer vulnerability context for each finding.
        cve_metadata = [
            scap_cve_index[cve_id]
            for cve_id in cve_ids
            if scap_cve_index and cve_id in scap_cve_index
        ]
        if not cve_ids:
            cve_status = "no_cves"
        elif scap_cve_index is None:
            cve_status = "metadata_unavailable"
        elif len(cve_metadata) == len(cve_ids):
            cve_status = "matched"
        elif cve_metadata:
            cve_status = "partial"
        else:
            cve_status = "not_found"

        enriched.append(
            _enriched_result(
                result,
                vt_metadata_status="matched",
                vt_metadata=select_vt_metadata_fields(entry),
                cve_ids=cve_ids,
                cve_metadata_status=cve_status,
                cve_metadata=cve_metadata,
            )
        )
    return enriched


def _format_enriched_result_for_log(enriched_result: dict[str, Any]) -> dict[str, Any]:
    """Hook for future log-specific formatting without changing callers."""
    return enriched_result


def dump_pretty_enriched_results(enriched_results: list[dict[str, Any]]) -> str:
    """Render enriched results as stable, human-readable JSON."""
    log_payload = [_format_enriched_result_for_log(result) for result in enriched_results]
    return json.dumps(log_payload, indent=2, sort_keys=True)


def load_scan_results(results_path: str | Path) -> list[dict[str, Any]]:
    """Load scanner results from disk and normalize the top-level payload shape."""
    payload = json.loads(Path(results_path).read_text(encoding="utf-8"))
    if isinstance(payload, list):
        results = payload
    elif isinstance(payload, dict) and isinstance(payload.get("results"), list):
        results = payload["results"]
    else:
        raise ValueError("Scanner results JSON must be a list or an object with a results list")

    if not all(isinstance(result, dict) for result in results):
        raise ValueError("Scanner results JSON must contain only result objects")
    return results


def enrich_results_from_files(
    *,
    results_path: str | Path,
    vt_metadata_path: str | Path,
    scap_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Load inputs from disk and run the standard enrichment pipeline."""
    results = load_scan_results(results_path)
    _metadata_path, vt_index = load_vt_metadata_index(vt_metadata_path)
    scap_cve_index = None
    if scap_path is not None:
        _paths, scap_cve_index = load_scap_cve_index(scap_path)
    return enrich_results(results, vt_index, scap_cve_index)


def build_parser() -> argparse.ArgumentParser:
    """Build the standalone enrichment CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Enrich OpenVAS scanner results with Greenbone feed metadata"
    )
    parser.add_argument(
        "--results",
        required=True,
        help="Path to scanner results JSON, either a result list or an object with a results list",
    )
    parser.add_argument(
        "--vt-metadata",
        required=True,
        help="Path to vt-metadata.json or a directory containing it",
    )
    parser.add_argument(
        "--scap-path",
        help="Optional path to Greenbone/NVD SCAP CVE JSON data for CVE enrichment",
    )
    parser.add_argument("--output", help="Write enriched JSON output to a file")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the standalone enrichment CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    enriched = enrich_results_from_files(
        results_path=args.results,
        vt_metadata_path=args.vt_metadata,
        scap_path=args.scap_path,
    )
    rendered = json.dumps(enriched, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
