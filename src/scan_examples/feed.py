"""Feed-loading utilities for VT metadata and SCAP CVE data."""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path
from typing import Any

VT_METADATA_FILENAME = "vt-metadata.json"
SCAP_JSON_GLOBS = ("*.json", "*.json.gz")
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def resolve_vt_metadata_path(vt_path: str | Path) -> Path:
    """Locate ``vt-metadata.json`` from either a file path or a feed directory."""
    base = Path(vt_path)
    if base.is_file():
        return base

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
    """Accept the common VT metadata JSON envelope shapes used in the wild."""
    if isinstance(payload, list):
        return [entry for entry in payload if isinstance(entry, dict)]
    if isinstance(payload, dict):
        for key in ("data", "results", "vts", "vt_metadata"):
            value = payload.get(key)
            if isinstance(value, list):
                return [entry for entry in value if isinstance(entry, dict)]
    raise ValueError("Unsupported VT metadata payload shape")


def load_vt_metadata_index(vt_path: str | Path) -> tuple[Path, dict[str, dict[str, Any]]]:
    """Load VT metadata and index it by OID for fast result lookups."""
    metadata_path = resolve_vt_metadata_path(vt_path)
    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    entries = _normalize_vt_metadata_payload(payload)
    index: dict[str, dict[str, Any]] = {}
    for entry in entries:
        oid = entry.get("oid")
        if isinstance(oid, str) and oid:
            index[oid] = entry
    return metadata_path, index


def resolve_scap_data_paths(scap_path: str | Path) -> list[Path]:
    """Resolve one file or a directory tree of SCAP/NVD JSON payloads."""
    base = Path(scap_path)
    if base.is_file():
        return [base]
    if not base.exists():
        raise FileNotFoundError(f"Could not find SCAP data under {base}")

    matches: list[Path] = []
    for glob in SCAP_JSON_GLOBS:
        matches.extend(path for path in base.rglob(glob) if path.is_file())
    matches = sorted(set(matches), key=lambda path: (len(path.parts), str(path)))
    if not matches:
        raise FileNotFoundError(f"Could not find SCAP JSON files under {base}")
    return matches


def _read_json_path(path: Path) -> Any:
    """Read plain or gzip-compressed JSON files."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return json.load(handle)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _iter_cve_entries(payload: Any):
    """Yield raw CVE entry objects from several supported SCAP/NVD formats."""
    if isinstance(payload, dict):
        vulnerabilities = payload.get("vulnerabilities")
        if isinstance(vulnerabilities, list):
            for item in vulnerabilities:
                if isinstance(item, dict):
                    cve = item.get("cve")
                    if isinstance(cve, dict):
                        yield cve
            return

        cve_items = payload.get("CVE_Items")
        if isinstance(cve_items, list):
            for item in cve_items:
                if isinstance(item, dict):
                    yield item
            return

        for key in ("data", "results", "cves"):
            value = payload.get(key)
            if isinstance(value, list):
                yield from _iter_cve_entries(value)
                return

    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                cve = item.get("cve")
                yield cve if isinstance(cve, dict) else item


def _extract_english_values(values: Any) -> list[str]:
    """Extract English or best-effort human-readable strings from value lists."""
    if not isinstance(values, list):
        return []
    selected: list[str] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        lang = value.get("lang") or value.get("language")
        text = value.get("value") or value.get("description")
        if isinstance(text, str) and (lang in (None, "en", "eng") or not selected):
            selected.append(text)
    return selected


def _extract_reference_urls(references: Any) -> list[str]:
    """Collect unique reference URLs from CVE metadata blocks."""
    refs = references.get("referenceData") if isinstance(references, dict) else references
    if not isinstance(refs, list):
        return []
    urls: list[str] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        url = ref.get("url") or ref.get("href") or ref.get("source")
        if isinstance(url, str) and url and url not in urls:
            urls.append(url)
    return urls


def _extract_weaknesses(weaknesses: Any, problemtype: Any = None) -> list[str]:
    """Collect CWE or weakness identifiers from CVE metadata."""
    ids: list[str] = []
    if isinstance(weaknesses, list):
        for weakness in weaknesses:
            if not isinstance(weakness, dict):
                continue
            for description in weakness.get("description", []):
                if isinstance(description, dict):
                    value = description.get("value")
                    if isinstance(value, str) and value not in ids:
                        ids.append(value)
    if isinstance(problemtype, dict):
        for item in problemtype.get("problemtype_data", []):
            if not isinstance(item, dict):
                continue
            for description in item.get("description", []):
                if isinstance(description, dict):
                    value = description.get("value")
                    if isinstance(value, str) and value not in ids:
                        ids.append(value)
    return ids


def _extract_cvss(metrics: Any, impact: Any = None) -> dict[str, Any]:
    """Select a compact CVSS view from either modern or legacy CVE schemas."""
    selected: dict[str, Any] = {}
    if isinstance(metrics, dict):
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key)
            if isinstance(values, list) and values:
                metric = values[0]
                if isinstance(metric, dict):
                    selected[key] = {
                        name: metric[name]
                        for name in ("source", "type", "baseSeverity", "exploitabilityScore", "impactScore")
                        if name in metric
                    }
                    cvss_data = metric.get("cvssData")
                    if isinstance(cvss_data, dict):
                        selected[key]["cvssData"] = {
                            name: cvss_data[name]
                            for name in ("version", "vectorString", "baseScore", "baseSeverity")
                            if name in cvss_data
                        }
    if isinstance(impact, dict):
        for key in ("baseMetricV3", "baseMetricV2"):
            metric = impact.get(key)
            if isinstance(metric, dict):
                selected[key] = metric
    return selected


def _extract_affected_cpes(configurations: Any) -> list[str]:
    """Collect affected CPE identifiers from nested configuration trees."""
    cpes: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("vulnerable") is True:
                cpe = value.get("criteria") or value.get("cpe23Uri")
                if isinstance(cpe, str) and cpe not in cpes:
                    cpes.append(cpe)
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(configurations)
    return cpes[:50]


def select_scap_cve_fields(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Reduce a raw CVE record to the fields the example actually uses."""
    cve_id = entry.get("id")
    if not isinstance(cve_id, str):
        meta = entry.get("cve", {}).get("CVE_data_meta") if isinstance(entry.get("cve"), dict) else entry.get("CVE_data_meta")
        if isinstance(meta, dict):
            cve_id = meta.get("ID")
    if not isinstance(cve_id, str):
        return None
    cve_id = cve_id.strip().upper()
    if not CVE_ID_PATTERN.fullmatch(cve_id):
        return None

    cve_body = entry.get("cve") if isinstance(entry.get("cve"), dict) else entry
    selected: dict[str, Any] = {"id": cve_id}
    for source, dest in (
        ("published", "published"),
        ("publishedDate", "published"),
        ("lastModified", "last_modified"),
        ("lastModifiedDate", "last_modified"),
        ("vulnStatus", "status"),
        ("sourceIdentifier", "source_identifier"),
    ):
        value = entry.get(source) if source in entry else cve_body.get(source)
        if value is not None and dest not in selected:
            selected[dest] = value

    descriptions = _extract_english_values(cve_body.get("descriptions"))
    if not descriptions and isinstance(cve_body.get("description"), dict):
        descriptions = _extract_english_values(cve_body["description"].get("description_data"))
    if descriptions:
        selected["descriptions"] = descriptions

    refs = _extract_reference_urls(cve_body.get("references") or entry.get("references"))
    if refs:
        selected["references"] = refs

    weaknesses = _extract_weaknesses(cve_body.get("weaknesses"), cve_body.get("problemtype"))
    if weaknesses:
        selected["weaknesses"] = weaknesses

    metrics = _extract_cvss(cve_body.get("metrics"), entry.get("impact"))
    if metrics:
        selected["metrics"] = metrics

    cpes = _extract_affected_cpes(cve_body.get("configurations") or entry.get("configurations"))
    if cpes:
        selected["affected_cpes"] = cpes

    return selected


def load_scap_cve_index(scap_path: str | Path) -> tuple[list[Path], dict[str, dict[str, Any]]]:
    """Load SCAP/NVD CVE data and index it by CVE id."""
    paths = resolve_scap_data_paths(scap_path)
    index: dict[str, dict[str, Any]] = {}
    for path in paths:
        payload = _read_json_path(path)
        for entry in _iter_cve_entries(payload):
            selected = select_scap_cve_fields(entry)
            if selected is not None:
                index[selected["id"]] = selected
    return paths, index


def select_vt_metadata_fields(entry: dict[str, Any]) -> dict[str, Any]:
    """Compatibility wrapper re-exported from :mod:`scan_examples.enrichment`."""
    from .enrichment import select_vt_metadata_fields as _select_vt_metadata_fields

    return _select_vt_metadata_fields(entry)


def extract_cve_ids_from_vt_metadata(entry: dict[str, Any] | None) -> list[str]:
    """Compatibility wrapper re-exported from :mod:`scan_examples.enrichment`."""
    from .enrichment import extract_cve_ids_from_vt_metadata as _extract_cve_ids

    return _extract_cve_ids(entry)


def extract_result_oid(result: dict[str, Any]) -> str | None:
    """Compatibility wrapper re-exported from :mod:`scan_examples.enrichment`."""
    from .enrichment import extract_result_oid as _extract_result_oid

    return _extract_result_oid(result)


def enrich_results(
    results: list[dict[str, Any]],
    vt_index: dict[str, dict[str, Any]] | None,
    scap_cve_index: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Compatibility wrapper re-exported from :mod:`scan_examples.enrichment`."""
    from .enrichment import enrich_results as _enrich_results

    return _enrich_results(results, vt_index, scap_cve_index)


def dump_pretty_enriched_results(enriched_results: list[dict[str, Any]]) -> str:
    """Compatibility wrapper re-exported from :mod:`scan_examples.enrichment`."""
    from .enrichment import dump_pretty_enriched_results as _dump_pretty

    return _dump_pretty(enriched_results)
