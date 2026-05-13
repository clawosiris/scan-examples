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


def resolve_scap_data_paths(scap_path: str | Path) -> list[Path]:
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
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return json.load(handle)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _iter_cve_entries(payload: Any):
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
            if isinstance(ref_id, str) and ref_id.upper().startswith("CVE-") and (ref_class is None or str(ref_class).lower() == "cve"):
                cve_ids.append(ref_id.upper())
    return sorted(set(cve_ids))


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
    scap_cve_index: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for result in results:
        oid = extract_result_oid(result)
        base: dict[str, Any] = {
            "result": result,
            "cve_ids": [],
            "cve_metadata_status": "no_cves",
            "cve_metadata": [],
        }
        if oid is None:
            enriched.append({**base, "vt_metadata_status": "missing_oid", "vt_metadata": None})
            continue

        if vt_index is None:
            enriched.append({**base, "vt_metadata_status": "metadata_unavailable", "vt_metadata": None})
            continue

        entry = vt_index.get(oid)
        if entry is None:
            enriched.append({**base, "vt_metadata_status": "not_found", "vt_metadata": None})
            continue

        cve_ids = extract_cve_ids_from_vt_metadata(entry)
        cve_metadata = [scap_cve_index[cve_id] for cve_id in cve_ids if scap_cve_index and cve_id in scap_cve_index]
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
            {
                **base,
                "vt_metadata_status": "matched",
                "vt_metadata": select_vt_metadata_fields(entry),
                "cve_ids": cve_ids,
                "cve_metadata_status": cve_status,
                "cve_metadata": cve_metadata,
            }
        )
    return enriched


def _format_enriched_result_for_log(enriched_result: dict[str, Any]) -> dict[str, Any]:
    return {
        "result": enriched_result.get("result"),
        "enrichment": {
            "vt_metadata_status": enriched_result.get("vt_metadata_status"),
            "vt_metadata": enriched_result.get("vt_metadata"),
            "cve_ids": enriched_result.get("cve_ids", []),
            "cve_metadata_status": enriched_result.get("cve_metadata_status", "no_cves"),
            "cve_metadata": enriched_result.get("cve_metadata", []),
        },
    }


def dump_pretty_enriched_results(enriched_results: list[dict[str, Any]]) -> str:
    log_payload = [_format_enriched_result_for_log(result) for result in enriched_results]
    return json.dumps(log_payload, indent=2, sort_keys=True)
