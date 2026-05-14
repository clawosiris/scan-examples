"""Feed-loading utilities for VT metadata, Notus advisories, and SCAP CVE data."""

import gzip
import json
import re
from pathlib import Path
from typing import Any

VT_METADATA_FILENAME = "vt-metadata.json"
NOTUS_FILE_GLOB = "*.notus"
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


def resolve_notus_advisory_paths(notus_path: str | Path) -> list[Path]:
    """Resolve one advisory file or a directory tree of ``.notus`` files."""
    base = Path(notus_path)
    if base.is_file():
        return [base]
    if not base.exists():
        raise FileNotFoundError(f"Could not find Notus advisories under {base}")

    matches = sorted(
        (path for path in base.rglob(NOTUS_FILE_GLOB) if path.is_file()),
        key=lambda path: (len(path.parts), str(path)),
    )
    if not matches:
        raise FileNotFoundError(f"Could not find Notus advisory files under {base}")
    return matches


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


def load_vt_metadata_index(
    vt_path: str | Path,
) -> tuple[Path, dict[str, dict[str, Any]]]:
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


def _notus_source_type(advisory_file: Path) -> str:
    """Classify a Notus file by its feed subdirectory role."""
    parts = advisory_file.parts
    if "advisories" in parts:
        return "advisory"
    if "products" in parts:
        return "product"
    return "generic"


def select_notus_advisory_fields(
    advisory: dict[str, Any],
    *,
    product_name: str | None,
    package_type: str | None,
    advisory_file: Path,
) -> dict[str, Any]:
    """Reduce a raw Notus advisory entry to the fields useful for enrichment."""
    selected: dict[str, Any] = {
        "oid": advisory.get("oid"),
        "advisory_file": advisory_file.name,
        "notus_source_type": _notus_source_type(advisory_file),
        "source_files": [advisory_file.name],
    }
    if product_name:
        selected["product_name"] = product_name
    if package_type:
        selected["package_type"] = package_type
    for key in (
        "title",
        "creation_date",
        "last_modification",
        "advisory_id",
        "advisory_xref",
        "summary",
        "insight",
        "affected",
        "qod_type",
        "severity",
    ):
        if key in advisory:
            selected[key] = advisory[key]

    cves = advisory.get("cves")
    if isinstance(cves, list):
        selected["cves"] = [cve for cve in cves if isinstance(cve, str)]

    xrefs = advisory.get("xrefs")
    if isinstance(xrefs, list):
        selected["xrefs"] = xrefs

    fixed_packages = advisory.get("fixed_packages")
    if isinstance(fixed_packages, list):
        selected["fixed_packages"] = [
            package for package in fixed_packages if isinstance(package, dict)
        ]
    return selected


def _json_dedup_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _merge_notus_entries(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge sparse product records with richer advisory records for one OID."""
    if not entries:
        raise ValueError("Cannot merge empty Notus entry set")

    def score(entry: dict[str, Any]) -> tuple[int, int]:
        rich_fields = sum(
            1
            for key in (
                "title",
                "advisory_id",
                "advisory_xref",
                "cves",
                "summary",
                "insight",
                "severity",
            )
            if entry.get(key)
        )
        source_bonus = 1 if entry.get("notus_source_type") == "advisory" else 0
        return (rich_fields, source_bonus)

    merged: dict[str, Any] = {}
    for entry in sorted(entries, key=score, reverse=True):
        for key, value in entry.items():
            if value in (None, [], {}, ""):
                continue
            if key in ("source_files",):
                merged.setdefault(key, [])
                for item in value:
                    if item not in merged[key]:
                        merged[key].append(item)
            elif key in ("cves", "xrefs", "fixed_packages"):
                merged.setdefault(key, [])
                seen = {_json_dedup_key(item) for item in merged[key]}
                for item in value:
                    item_key = _json_dedup_key(item)
                    if item_key not in seen:
                        merged[key].append(item)
                        seen.add(item_key)
            elif key not in merged:
                merged[key] = value
    return merged


def load_notus_advisory_index(
    notus_path: str | Path,
) -> tuple[list[Path], dict[str, list[dict[str, Any]]]]:
    """Load Notus advisory files and index them by advisory OID.

    A single OID may appear in more than one OS advisory file, so the index maps
    each OID to a list of matching advisory snippets instead of a single object.
    """
    paths = resolve_notus_advisory_paths(notus_path)
    index: dict[str, list[dict[str, Any]]] = {}
    for path in paths:
        payload = _read_json_path(path)
        if not isinstance(payload, dict):
            raise ValueError(f"Unsupported Notus advisory payload shape in {path}")

        product_name = payload.get("product_name")
        if not isinstance(product_name, str):
            product_name = None
        package_type = payload.get("package_type")
        if not isinstance(package_type, str):
            package_type = None

        advisories = payload.get("advisories")
        if not isinstance(advisories, list):
            continue

        for advisory in advisories:
            if not isinstance(advisory, dict):
                continue
            oid = advisory.get("oid")
            if not isinstance(oid, str) or not oid:
                continue
            index.setdefault(oid, []).append(
                select_notus_advisory_fields(
                    advisory,
                    product_name=product_name,
                    package_type=package_type,
                    advisory_file=path,
                )
            )

    merged_index: dict[str, list[dict[str, Any]]] = {}
    for oid, advisories in index.items():
        merged_index[oid] = [_merge_notus_entries(advisories)]

    return paths, merged_index


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
    """Extract English strings, or fall back to the first available description."""
    if not isinstance(values, list):
        return []
    english: list[str] = []
    fallback: str | None = None
    for value in values:
        if not isinstance(value, dict):
            continue
        lang = value.get("lang") or value.get("language")
        text = value.get("value") or value.get("description")
        if not isinstance(text, str):
            continue
        if fallback is None:
            fallback = text
        if lang in (None, "en", "eng"):
            english.append(text)
    return english or ([fallback] if fallback is not None else [])


def _extract_reference_urls(references: Any) -> list[str]:
    """Collect unique reference URLs from CVE metadata blocks."""
    refs = (
        references.get("referenceData") if isinstance(references, dict) else references
    )
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
                        for name in (
                            "source",
                            "type",
                            "baseSeverity",
                            "exploitabilityScore",
                            "impactScore",
                        )
                        if name in metric
                    }
                    cvss_data = metric.get("cvssData")
                    if isinstance(cvss_data, dict):
                        selected[key]["cvssData"] = {
                            name: cvss_data[name]
                            for name in (
                                "version",
                                "vectorString",
                                "baseScore",
                                "baseSeverity",
                            )
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
        meta = (
            entry.get("cve", {}).get("CVE_data_meta")
            if isinstance(entry.get("cve"), dict)
            else entry.get("CVE_data_meta")
        )
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
        descriptions = _extract_english_values(
            cve_body["description"].get("description_data")
        )
    if descriptions:
        selected["descriptions"] = descriptions

    refs = _extract_reference_urls(
        cve_body.get("references") or entry.get("references")
    )
    if refs:
        selected["references"] = refs

    weaknesses = _extract_weaknesses(
        cve_body.get("weaknesses"), cve_body.get("problemtype")
    )
    if weaknesses:
        selected["weaknesses"] = weaknesses

    metrics = _extract_cvss(cve_body.get("metrics"), entry.get("impact"))
    if metrics:
        selected["metrics"] = metrics

    cpes = _extract_affected_cpes(
        cve_body.get("configurations") or entry.get("configurations")
    )
    if cpes:
        selected["affected_cpes"] = cpes

    return selected


def load_scap_cve_index(
    scap_path: str | Path,
) -> tuple[list[Path], dict[str, dict[str, Any]]]:
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
    notus_index: dict[str, list[dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    """Compatibility wrapper re-exported from :mod:`scan_examples.enrichment`."""
    from .enrichment import enrich_results as _enrich_results

    return _enrich_results(results, vt_index, scap_cve_index, notus_index)


def dump_pretty_enriched_results(enriched_results: list[dict[str, Any]]) -> str:
    """Compatibility wrapper re-exported from :mod:`scan_examples.enrichment`."""
    from .enrichment import dump_pretty_enriched_results as _dump_pretty

    return _dump_pretty(enriched_results)
