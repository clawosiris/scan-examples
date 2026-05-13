from __future__ import annotations

import json
from pathlib import Path
from typing import Any

VT_METADATA_FILENAME = "vt-metadata.json"


def resolve_vt_metadata_path(vt_path: str | Path) -> Path:
    base = Path(vt_path)
    candidates = [
        base / VT_METADATA_FILENAME,
        base / "nasl" / VT_METADATA_FILENAME,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate

    recursive_matches = sorted(
        (path for path in base.rglob(VT_METADATA_FILENAME) if path.is_file()),
        key=lambda path: (len(path.parts), str(path)),
    )
    if recursive_matches:
        return recursive_matches[0]

    raise FileNotFoundError(f"Could not find {VT_METADATA_FILENAME} under {base}")


def _normalize_vt_metadata_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [entry for entry in payload if isinstance(entry, dict)]
    if isinstance(payload, dict):
        for key in ("data", "results", "vts", "vt_metadata"):
            value = payload.get(key)
            if isinstance(value, list):
                return [entry for entry in value if isinstance(entry, dict)]
    raise ValueError("Unsupported VT metadata payload shape")


def load_vt_metadata_index(vt_path: str | Path) -> tuple[Path, dict[str, dict[str, Any]]]:
    metadata_path = resolve_vt_metadata_path(vt_path)
    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    entries = _normalize_vt_metadata_payload(payload)
    index: dict[str, dict[str, Any]] = {}
    for entry in entries:
        oid = entry.get("oid")
        if isinstance(oid, str) and oid:
            index[oid] = entry
    return metadata_path, index


def select_vt_metadata_fields(entry: dict[str, Any]) -> dict[str, Any]:
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


def extract_result_oid(result: dict[str, Any]) -> str | None:
    oid = result.get("oid")
    if isinstance(oid, str) and oid:
        return oid

    nvt = result.get("nvt")
    if isinstance(nvt, dict):
        nested_oid = nvt.get("oid")
        if isinstance(nested_oid, str) and nested_oid:
            return nested_oid

    return None


def enrich_results(
    results: list[dict[str, Any]],
    vt_index: dict[str, dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for result in results:
        oid = extract_result_oid(result)
        if oid is None:
            enriched.append(
                {
                    "result": result,
                    "vt_metadata_status": "missing_oid",
                    "vt_metadata": None,
                }
            )
            continue

        if vt_index is None:
            enriched.append(
                {
                    "result": result,
                    "vt_metadata_status": "metadata_unavailable",
                    "vt_metadata": None,
                }
            )
            continue

        entry = vt_index.get(oid)
        if entry is None:
            enriched.append(
                {
                    "result": result,
                    "vt_metadata_status": "not_found",
                    "vt_metadata": None,
                }
            )
            continue

        enriched.append(
            {
                "result": result,
                "vt_metadata_status": "matched",
                "vt_metadata": select_vt_metadata_fields(entry),
            }
        )
    return enriched


def dump_pretty_enriched_results(enriched_results: list[dict[str, Any]]) -> str:
    return json.dumps(enriched_results, indent=2, sort_keys=True)
