//! Enrichment helpers for OpenVAS scanner result payloads.
//!
//! The crate supports both the in-process library path used by Python bindings and the
//! standalone CLI path used for large offline enrichment jobs. The CLI-focused path prefers
//! streaming where possible so very large result sets do not have to be materialized twice.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use flate2::read::GzDecoder;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::{Deserializer, Map, Value};
use walkdir::WalkDir;

/// Default VT metadata filename used when the caller points at a feed directory.
const VT_METADATA_FILENAME: &str = "vt-metadata.json";
/// Prefix used when normalizing CVE identifiers from mixed metadata sources.
const CVE_PREFIX: &str = "CVE-";

/// Run the standalone enrichment flow and write JSON output to a file or stdout.
pub fn run_cli(
    results_path: &Path,
    vt_metadata_path: Option<&Path>,
    notus_path: Option<&Path>,
    scap_path: Option<&Path>,
    output_path: Option<&Path>,
) -> Result<()> {
    if let Some(path) = output_path {
        let file = fs::File::create(path)
            .with_context(|| format!("Failed to create {}", path.display()))?;
        let writer = std::io::BufWriter::new(file);
        enrich_results_from_files_to_writer(
            results_path,
            vt_metadata_path,
            notus_path,
            scap_path,
            writer,
        )?;
    } else {
        let stdout = std::io::stdout();
        let writer = std::io::BufWriter::new(stdout.lock());
        enrich_results_from_files_to_writer(
            results_path,
            vt_metadata_path,
            notus_path,
            scap_path,
            writer,
        )?;
    }
    Ok(())
}

/// Load scan results from disk, resolve the relevant metadata indexes, and return enriched JSON.
pub fn enrich_results_from_files(
    results_path: &Path,
    vt_metadata_path: Option<&Path>,
    notus_path: Option<&Path>,
    scap_path: Option<&Path>,
) -> Result<Vec<Value>> {
    let results = load_results(results_path)?;
    let oids = collect_oids(&results);

    let vt_index = match vt_metadata_path {
        Some(path) => Some(load_vt_metadata_index(path, &oids)?),
        None => None,
    };
    let notus_index = match notus_path {
        Some(path) => Some(load_notus_advisory_index(path, &oids)?),
        None => None,
    };
    let cve_ids = collect_needed_cve_ids(vt_index.as_ref(), notus_index.as_ref());
    let scap_index = match scap_path {
        Some(path) if !cve_ids.is_empty() => Some(load_scap_cve_index(path, &cve_ids)?),
        Some(_) => Some(HashMap::new()),
        None => None,
    };

    Ok(enrich_results(
        results,
        vt_index.as_ref(),
        notus_index.as_ref(),
        scap_index.as_ref(),
    ))
}

/// Stream scan results from disk, enrich each one, and write the output incrementally.
///
/// This avoids loading the fully enriched result set into memory, which matters for large
/// offline benchmarking and export flows.
pub fn enrich_results_from_files_to_writer<W: Write>(
    results_path: &Path,
    vt_metadata_path: Option<&Path>,
    notus_path: Option<&Path>,
    scap_path: Option<&Path>,
    mut writer: W,
) -> Result<()> {
    let oids = collect_oids_from_results_path(results_path)?;
    let vt_index = match vt_metadata_path {
        Some(path) => Some(load_vt_metadata_index(path, &oids)?),
        None => None,
    };
    let notus_index = match notus_path {
        Some(path) => Some(load_notus_advisory_index(path, &oids)?),
        None => None,
    };
    let cve_ids = collect_needed_cve_ids(vt_index.as_ref(), notus_index.as_ref());
    let scap_index = match scap_path {
        Some(path) if !cve_ids.is_empty() => Some(load_scap_cve_index(path, &cve_ids)?),
        Some(_) => Some(HashMap::new()),
        None => None,
    };

    writer.write_all(b"[")?;
    let mut first = true;
    stream_results(results_path, |result| {
        let enriched = enrich_one_result(
            result,
            vt_index.as_ref(),
            notus_index.as_ref(),
            scap_index.as_ref(),
        );
        if !first {
            writer.write_all(b",\n")?;
        } else {
            first = false;
        }
        serde_json::to_writer(&mut writer, &enriched)?;
        Ok(())
    })?;
    if !first {
        writer.write_all(b"\n")?;
    }
    writer.write_all(b"]\n")?;
    writer.flush()?;
    Ok(())
}

fn load_results(path: &Path) -> Result<Vec<Map<String, Value>>> {
    let mut results = Vec::new();
    stream_results(path, |result| {
        results.push(result);
        Ok(())
    })?;
    Ok(results)
}

/// Collect all OIDs present in an already-loaded result slice.
fn collect_oids(results: &[Map<String, Value>]) -> HashSet<String> {
    results.iter().filter_map(extract_result_oid).collect()
}

/// Collect all OIDs referenced by a result file without keeping the full payload in memory.
fn collect_oids_from_results_path(path: &Path) -> Result<HashSet<String>> {
    let mut oids = HashSet::new();
    stream_results(path, |result| {
        if let Some(oid) = extract_result_oid(&result) {
            oids.insert(oid);
        }
        Ok(())
    })?;
    Ok(oids)
}

/// Collect the CVE identifiers referenced by the selected VT and Notus metadata entries.
fn collect_needed_cve_ids(
    vt_index: Option<&HashMap<String, Value>>,
    notus_index: Option<&HashMap<String, Vec<Value>>>,
) -> BTreeSet<String> {
    let mut cve_ids = BTreeSet::new();
    if let Some(index) = vt_index {
        for entry in index.values() {
            for cve in extract_cve_ids_from_vt_metadata(entry) {
                cve_ids.insert(cve);
            }
        }
    }
    if let Some(index) = notus_index {
        for entries in index.values() {
            for cve in extract_cve_ids_from_notus_metadata(entries) {
                cve_ids.insert(cve);
            }
        }
    }
    cve_ids
}

/// Stream result objects from a raw `[...]` payload or a wrapped `{ "results": [...] }` object.
///
/// The callback-based shape lets callers perform a lightweight first pass for OID discovery and
/// a second pass for enrichment/output without allocating an entire intermediate result vector.
fn stream_results<F>(path: &Path, mut callback: F) -> Result<()>
where
    F: FnMut(Map<String, Value>) -> Result<()>,
{
    let file =
        fs::File::open(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let mut reader: Box<dyn BufRead> =
        if path.extension().and_then(|value| value.to_str()) == Some("gz") {
            Box::new(BufReader::new(GzDecoder::new(file)))
        } else {
            Box::new(BufReader::new(file))
        };
    // Peek just far enough to decide whether the payload is a bare array or a wrapped object,
    // then hand the same buffered reader to serde so parsing resumes from the correct position.
    let first = first_non_whitespace_byte(&mut reader)?
        .ok_or_else(|| anyhow!("Scanner results JSON must not be empty"))?;
    let mut deserializer = Deserializer::from_reader(reader);
    match first {
        b'[' => {
            let seed = ResultArraySeed {
                callback: &mut callback,
            };
            seed.deserialize(&mut deserializer)?;
        }
        b'{' => {
            let seed = ResultsObjectSeed {
                callback: &mut callback,
            };
            seed.deserialize(&mut deserializer)?;
        }
        _ => {
            return Err(anyhow!(
                "Scanner results JSON must be a list or an object with a results list"
            ));
        }
    }
    Ok(())
}

/// Return the first non-whitespace byte from a buffered reader without consuming it.
fn first_non_whitespace_byte<R: BufRead>(reader: &mut R) -> Result<Option<u8>> {
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(None);
        }
        let consumed = buffer
            .iter()
            .take_while(|byte| byte.is_ascii_whitespace())
            .count();
        if consumed < buffer.len() {
            return Ok(Some(buffer[consumed]));
        }
        reader.consume(consumed);
    }
}

/// Deserialize a top-level JSON array by invoking a callback for each result object.
struct ResultArraySeed<'a, F> {
    callback: &'a mut F,
}

impl<'de, 'a, F> DeserializeSeed<'de> for ResultArraySeed<'a, F>
where
    F: FnMut(Map<String, Value>) -> Result<()>,
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(ResultArrayVisitor {
            callback: self.callback,
        })
    }
}

/// Visitor used for array-shaped result payloads.
struct ResultArrayVisitor<'a, F> {
    callback: &'a mut F,
}

impl<'de, 'a, F> Visitor<'de> for ResultArrayVisitor<'a, F>
where
    F: FnMut(Map<String, Value>) -> Result<()>,
{
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON array of scan result objects")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(item) = seq.next_element::<Map<String, Value>>()? {
            (self.callback)(item).map_err(serde::de::Error::custom)?;
        }
        Ok(())
    }
}

/// Deserialize an object-shaped payload and stream only its `results` array entries.
struct ResultsObjectSeed<'a, F> {
    callback: &'a mut F,
}

impl<'de, 'a, F> DeserializeSeed<'de> for ResultsObjectSeed<'a, F>
where
    F: FnMut(Map<String, Value>) -> Result<()>,
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(ResultsObjectVisitor {
            callback: self.callback,
        })
    }
}

/// Visitor used for wrapped payloads that contain a `results` array among other keys.
struct ResultsObjectVisitor<'a, F> {
    callback: &'a mut F,
}

impl<'de, 'a, F> Visitor<'de> for ResultsObjectVisitor<'a, F>
where
    F: FnMut(Map<String, Value>) -> Result<()>,
{
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an object containing a results array")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut found_results = false;
        while let Some(key) = map.next_key::<String>()? {
            if key == "results" {
                found_results = true;
                let seed = ResultArraySeed {
                    callback: self.callback,
                };
                // Stream the nested array directly so wrapper metadata like `scan_id` can be
                // ignored without buffering the entire object payload in memory.
                map.next_value_seed(seed)?;
            } else {
                let _: IgnoredAny = map.next_value()?;
            }
        }
        if !found_results {
            return Err(serde::de::Error::custom(
                "Scanner results JSON must be a list or an object with a results list",
            ));
        }
        Ok(())
    }
}

/// Extract and normalize the OID from a scan result object if present.
fn extract_result_oid(result: &Map<String, Value>) -> Option<String> {
    if let Some(Value::String(oid)) = result.get("oid") {
        if !oid.is_empty() {
            return Some(oid.clone());
        }
    }
    if let Some(Value::Object(nvt)) = result.get("nvt") {
        if let Some(Value::String(oid)) = nvt.get("oid") {
            if !oid.is_empty() {
                return Some(oid.clone());
            }
        }
    }
    None
}

/// Resolve a VT metadata file path from either a direct file path or a feed directory.
fn resolve_vt_metadata_path(path: &Path) -> Result<PathBuf> {
    if path.is_file() {
        return Ok(path.to_path_buf());
    }
    for candidate in [
        path.join(VT_METADATA_FILENAME),
        path.join("nasl").join(VT_METADATA_FILENAME),
    ] {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    let mut matches = WalkDir::new(path)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_file() && entry.file_name() == VT_METADATA_FILENAME)
        .map(|entry| entry.into_path())
        .collect::<Vec<_>>();
    matches.sort();
    matches.into_iter().next().ok_or_else(|| {
        anyhow!(
            "Could not find {VT_METADATA_FILENAME} under {}",
            path.display()
        )
    })
}

/// Load only the VT metadata entries needed for the supplied OID set.
fn load_vt_metadata_index(
    path: &Path,
    needed_oids: &HashSet<String>,
) -> Result<HashMap<String, Value>> {
    let metadata_path = resolve_vt_metadata_path(path)?;
    let payload = read_json(&metadata_path)?;
    let entries = normalize_vt_metadata_payload(payload)?;
    let mut index = HashMap::new();
    for entry in entries {
        if let Value::Object(obj) = entry {
            if let Some(Value::String(oid)) = obj.get("oid") {
                if needed_oids.contains(oid) {
                    index.insert(oid.clone(), select_vt_metadata_fields(&obj));
                }
            }
        }
    }
    Ok(index)
}

/// Normalize supported VT metadata payload shapes into a flat list of entries.
fn normalize_vt_metadata_payload(payload: Value) -> Result<Vec<Value>> {
    match payload {
        Value::Array(items) => Ok(items),
        Value::Object(obj) => {
            for key in ["data", "results", "vts", "vt_metadata"] {
                if let Some(Value::Array(items)) = obj.get(key) {
                    return Ok(items.clone());
                }
            }
            Err(anyhow!("Unsupported VT metadata payload shape"))
        }
        _ => Err(anyhow!("Unsupported VT metadata payload shape")),
    }
}

/// Keep only the VT metadata fields that are useful in enriched output.
fn select_vt_metadata_fields(entry: &Map<String, Value>) -> Value {
    let mut selected = Map::new();
    for key in [
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
    ] {
        if let Some(value) = entry.get(key) {
            selected.insert(key.to_string(), value.clone());
        }
    }
    Value::Object(selected)
}

/// Extract normalized CVE identifiers from a VT metadata entry.
fn extract_cve_ids_from_vt_metadata(entry: &Value) -> Vec<String> {
    let mut cves = BTreeSet::new();
    let Some(obj) = entry.as_object() else {
        return Vec::new();
    };
    let Some(Value::Array(references)) = obj.get("references") else {
        return Vec::new();
    };
    for reference in references {
        let Some(reference_obj) = reference.as_object() else {
            continue;
        };
        let Some(Value::String(id)) = reference_obj.get("id") else {
            continue;
        };
        let upper = id.to_uppercase();
        if !upper.starts_with(CVE_PREFIX) {
            continue;
        }
        let class_ok = match reference_obj.get("class") {
            Some(Value::String(class)) => class.eq_ignore_ascii_case("cve"),
            None => true,
            _ => false,
        };
        if class_ok {
            cves.insert(upper);
        }
    }
    cves.into_iter().collect()
}

/// Resolve one or more Notus advisory files from a directory or a single file path.
fn resolve_notus_advisory_paths(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.exists() {
        return Err(anyhow!(
            "Could not find Notus advisories under {}",
            path.display()
        ));
    }
    let mut matches = WalkDir::new(path)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|candidate| candidate.extension().and_then(|value| value.to_str()) == Some("notus"))
        .collect::<Vec<_>>();
    matches.sort();
    if matches.is_empty() {
        return Err(anyhow!(
            "Could not find Notus advisory files under {}",
            path.display()
        ));
    }
    Ok(matches)
}

/// Load advisory entries for the requested OIDs from Notus JSON files.
fn load_notus_advisory_index(
    path: &Path,
    needed_oids: &HashSet<String>,
) -> Result<HashMap<String, Vec<Value>>> {
    let paths = resolve_notus_advisory_paths(path)?;
    let mut raw_index: HashMap<String, Vec<Map<String, Value>>> = HashMap::new();
    for advisory_path in paths {
        let payload = read_json(&advisory_path)?;
        let Some(obj) = payload.as_object() else {
            return Err(anyhow!(
                "Unsupported Notus advisory payload shape in {}",
                advisory_path.display()
            ));
        };
        let product_name = obj
            .get("product_name")
            .and_then(Value::as_str)
            .map(str::to_string);
        let package_type = obj
            .get("package_type")
            .and_then(Value::as_str)
            .map(str::to_string);
        let Some(Value::Array(advisories)) = obj.get("advisories") else {
            continue;
        };
        for advisory in advisories {
            let Some(advisory_obj) = advisory.as_object() else {
                continue;
            };
            let Some(oid) = advisory_obj.get("oid").and_then(Value::as_str) else {
                continue;
            };
            if !needed_oids.contains(oid) {
                continue;
            }
            raw_index
                .entry(oid.to_string())
                .or_default()
                .push(select_notus_advisory_fields(
                    advisory_obj,
                    product_name.as_deref(),
                    package_type.as_deref(),
                    &advisory_path,
                ));
        }
    }

    let mut merged = HashMap::new();
    for (oid, entries) in raw_index {
        merged.insert(oid, vec![Value::Object(merge_notus_entries(entries))]);
    }
    Ok(merged)
}

/// Classify a Notus source file so merged output can preserve where entries came from.
fn notus_source_type(path: &Path) -> &'static str {
    for part in path.iter() {
        if part == "advisories" {
            return "advisory";
        }
        if part == "products" {
            return "product";
        }
    }
    "generic"
}

/// Project a Notus advisory entry into the subset of fields exposed in enriched output.
fn select_notus_advisory_fields(
    advisory: &Map<String, Value>,
    product_name: Option<&str>,
    package_type: Option<&str>,
    advisory_file: &Path,
) -> Map<String, Value> {
    let mut selected = Map::new();
    selected.insert(
        "oid".to_string(),
        advisory.get("oid").cloned().unwrap_or(Value::Null),
    );
    selected.insert(
        "advisory_file".to_string(),
        Value::String(
            advisory_file
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_string(),
        ),
    );
    selected.insert(
        "notus_source_type".to_string(),
        Value::String(notus_source_type(advisory_file).to_string()),
    );
    selected.insert(
        "source_files".to_string(),
        Value::Array(vec![Value::String(
            advisory_file
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_string(),
        )]),
    );
    if let Some(product_name) = product_name {
        selected.insert(
            "product_name".to_string(),
            Value::String(product_name.to_string()),
        );
    }
    if let Some(package_type) = package_type {
        selected.insert(
            "package_type".to_string(),
            Value::String(package_type.to_string()),
        );
    }
    for key in [
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
    ] {
        if let Some(value) = advisory.get(key) {
            selected.insert(key.to_string(), value.clone());
        }
    }
    if let Some(Value::Array(cves)) = advisory.get("cves") {
        selected.insert(
            "cves".to_string(),
            Value::Array(
                cves.iter()
                    .filter(|value| value.is_string())
                    .cloned()
                    .collect(),
            ),
        );
    }
    if let Some(Value::Array(xrefs)) = advisory.get("xrefs") {
        selected.insert("xrefs".to_string(), Value::Array(xrefs.clone()));
    }
    if let Some(Value::Array(fixed_packages)) = advisory.get("fixed_packages") {
        selected.insert(
            "fixed_packages".to_string(),
            Value::Array(
                fixed_packages
                    .iter()
                    .filter(|value| value.is_object())
                    .cloned()
                    .collect(),
            ),
        );
    }
    selected
}

/// Merge multiple Notus entries for the same OID into one richer synthetic advisory document.
fn merge_notus_entries(entries: Vec<Map<String, Value>>) -> Map<String, Value> {
    let mut entries = entries;
    // Merge the richest advisory first so scalar fields prefer the most informative source,
    // then append array-like data from less-rich entries without losing unique values.
    entries.sort_by_key(|entry| (notus_richness_score(entry), advisory_bonus(entry)));
    entries.reverse();

    let mut merged = Map::new();
    for entry in entries {
        for (key, value) in entry {
            if is_empty_value(&value) {
                continue;
            }
            match key.as_str() {
                "source_files" => merge_unique_array(&mut merged, &key, &value),
                "cves" | "xrefs" | "fixed_packages" => {
                    merge_unique_array(&mut merged, &key, &value)
                }
                _ => {
                    merged.entry(key).or_insert(value);
                }
            }
        }
    }
    merged
}

/// Prefer advisory-backed Notus entries when ranking merge candidates.
fn advisory_bonus(entry: &Map<String, Value>) -> i32 {
    matches!(entry.get("notus_source_type"), Some(Value::String(kind)) if kind == "advisory") as i32
}

/// Score a Notus entry by how much useful data it contributes to merged output.
fn notus_richness_score(entry: &Map<String, Value>) -> i32 {
    [
        "title",
        "advisory_id",
        "advisory_xref",
        "cves",
        "summary",
        "insight",
        "severity",
    ]
    .iter()
    .filter(|key| entry.get(**key).is_some_and(|value| !is_empty_value(value)))
    .count() as i32
}

/// Merge array values while preserving order and removing JSON-equivalent duplicates.
fn merge_unique_array(target: &mut Map<String, Value>, key: &str, value: &Value) {
    let Value::Array(items) = value else {
        return;
    };
    let entry = target
        .entry(key.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let Value::Array(current) = entry else {
        return;
    };
    let mut seen = current
        .iter()
        .map(normalized_json_key)
        .collect::<HashSet<_>>();
    for item in items {
        let candidate = normalized_json_key(item);
        if seen.insert(candidate) {
            current.push(item.clone());
        }
    }
}

/// Generate a stable deduplication key for arbitrary JSON values.
fn normalized_json_key(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Treat null, empty strings, empty arrays, and empty objects as absent values.
fn is_empty_value(value: &Value) -> bool {
    matches!(value, Value::Null)
        || matches!(value, Value::String(s) if s.is_empty())
        || matches!(value, Value::Array(items) if items.is_empty())
        || matches!(value, Value::Object(map) if map.is_empty())
}

/// Extract normalized CVE identifiers from merged Notus metadata entries.
fn extract_cve_ids_from_notus_metadata(entries: &[Value]) -> Vec<String> {
    let mut cves = BTreeSet::new();
    for entry in entries {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        let Some(Value::Array(values)) = obj.get("cves") else {
            continue;
        };
        for value in values {
            if let Some(cve) = value.as_str() {
                let upper = cve.to_uppercase();
                if upper.starts_with(CVE_PREFIX) {
                    cves.insert(upper);
                }
            }
        }
    }
    cves.into_iter().collect()
}

/// Resolve one or more SCAP data files from a directory or a single file path.
fn resolve_scap_data_paths(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.exists() {
        return Err(anyhow!("Could not find SCAP data under {}", path.display()));
    }
    let mut matches = WalkDir::new(path)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|candidate| {
            matches!(
                candidate.extension().and_then(|value| value.to_str()),
                Some("json") | Some("gz")
            )
        })
        .collect::<Vec<_>>();
    matches.sort();
    if matches.is_empty() {
        return Err(anyhow!(
            "Could not find SCAP JSON files under {}",
            path.display()
        ));
    }
    Ok(matches)
}

/// Load only the SCAP CVE entries referenced by the selected VT/Notus metadata.
fn load_scap_cve_index(
    path: &Path,
    needed_cves: &BTreeSet<String>,
) -> Result<HashMap<String, Value>> {
    let paths = resolve_scap_data_paths(path)?;
    let mut index = HashMap::new();
    for data_path in paths {
        let payload = read_json(&data_path)?;
        iter_cve_entries(&payload, &mut |entry| {
            if let Some(selected) = select_scap_cve_fields(entry) {
                if let Some(id) = selected.get("id").and_then(Value::as_str) {
                    if needed_cves.contains(id) {
                        index.insert(id.to_string(), Value::Object(selected));
                    }
                }
            }
        });
    }
    Ok(index)
}

/// Iterate over supported SCAP payload layouts and invoke a callback for each CVE object.
fn iter_cve_entries<F: FnMut(&Map<String, Value>)>(payload: &Value, callback: &mut F) {
    match payload {
        Value::Array(items) => {
            for item in items {
                if let Some(obj) = item.as_object() {
                    if let Some(cve) = obj.get("cve").and_then(Value::as_object) {
                        callback(cve);
                    } else {
                        callback(obj);
                    }
                }
            }
        }
        Value::Object(obj) => {
            // Different SCAP exports wrap CVE data under different top-level keys; handle the
            // common cases explicitly before falling back to a small recursive search.
            if let Some(Value::Array(vulnerabilities)) = obj.get("vulnerabilities") {
                for item in vulnerabilities {
                    if let Some(cve) = item.get("cve").and_then(Value::as_object) {
                        callback(cve);
                    }
                }
                return;
            }
            if let Some(Value::Array(items)) = obj.get("CVE_Items") {
                for item in items {
                    if let Some(item_obj) = item.as_object() {
                        callback(item_obj);
                    }
                }
                return;
            }
            for key in ["data", "results", "cves"] {
                if let Some(value) = obj.get(key) {
                    iter_cve_entries(value, callback);
                    return;
                }
            }
        }
        _ => {}
    }
}

/// Project a SCAP CVE entry into the subset of fields exposed in enriched output.
fn select_scap_cve_fields(entry: &Map<String, Value>) -> Option<Map<String, Value>> {
    let cve_body = entry.get("cve").and_then(Value::as_object).unwrap_or(entry);
    let cve_id = entry
        .get("id")
        .and_then(Value::as_str)
        .or_else(|| cve_body.get("id").and_then(Value::as_str))
        .or_else(|| {
            cve_body
                .get("CVE_data_meta")
                .and_then(Value::as_object)
                .and_then(|meta| meta.get("ID"))
                .and_then(Value::as_str)
        })?
        .trim()
        .to_uppercase();
    if !cve_id.starts_with(CVE_PREFIX) {
        return None;
    }

    let mut selected = Map::new();
    selected.insert("id".to_string(), Value::String(cve_id));
    copy_first_string(
        entry,
        cve_body,
        &["published", "publishedDate"],
        &mut selected,
        "published",
    );
    copy_first_string(
        entry,
        cve_body,
        &["lastModified", "lastModifiedDate"],
        &mut selected,
        "last_modified",
    );
    copy_first_string(entry, cve_body, &["vulnStatus"], &mut selected, "status");
    copy_first_string(
        entry,
        cve_body,
        &["sourceIdentifier"],
        &mut selected,
        "source_identifier",
    );

    if let Some(descriptions) = extract_english_values(cve_body.get("descriptions")).or_else(|| {
        cve_body
            .get("description")
            .and_then(Value::as_object)
            .and_then(|desc| extract_english_values(desc.get("description_data")))
    }) {
        selected.insert(
            "descriptions".to_string(),
            Value::Array(descriptions.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(references) = extract_reference_urls(
        cve_body
            .get("references")
            .or_else(|| entry.get("references")),
    ) {
        selected.insert(
            "references".to_string(),
            Value::Array(references.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(weaknesses) =
        extract_weaknesses(cve_body.get("weaknesses"), cve_body.get("problemtype"))
    {
        selected.insert(
            "weaknesses".to_string(),
            Value::Array(weaknesses.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(metrics) = extract_cvss(cve_body.get("metrics"), entry.get("impact")) {
        selected.insert("metrics".to_string(), Value::Object(metrics));
    }
    if let Some(cpes) = extract_affected_cpes(
        cve_body
            .get("configurations")
            .or_else(|| entry.get("configurations")),
    ) {
        selected.insert(
            "affected_cpes".to_string(),
            Value::Array(cpes.into_iter().map(Value::String).collect()),
        );
    }
    Some(selected)
}

/// Copy the first string value found under `source_key` into `selected[target_key]`.
fn copy_first_string(
    entry: &Map<String, Value>,
    cve_body: &Map<String, Value>,
    keys: &[&str],
    target: &mut Map<String, Value>,
    destination: &str,
) {
    for key in keys {
        if let Some(value) = entry
            .get(*key)
            .and_then(Value::as_str)
            .or_else(|| cve_body.get(*key).and_then(Value::as_str))
        {
            target.insert(destination.to_string(), Value::String(value.to_string()));
            return;
        }
    }
}

/// Extract English-language text values from common SCAP language-tagged arrays.
fn extract_english_values(value: Option<&Value>) -> Option<Vec<String>> {
    let Value::Array(items) = value? else {
        return None;
    };
    let mut english = Vec::new();
    let mut fallback: Option<String> = None;
    for item in items {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let text = obj
            .get("value")
            .and_then(Value::as_str)
            .or_else(|| obj.get("description").and_then(Value::as_str));
        let Some(text) = text else {
            continue;
        };
        let lang = obj
            .get("lang")
            .and_then(Value::as_str)
            .or_else(|| obj.get("language").and_then(Value::as_str));
        if fallback.is_none() {
            fallback = Some(text.to_string());
        }
        if matches!(lang, None | Some("en") | Some("eng")) {
            english.push(text.to_string());
        }
    }
    if !english.is_empty() {
        Some(english)
    } else {
        fallback.map(|value| vec![value])
    }
}

/// Extract reference URLs from common SCAP reference payload shapes.
fn extract_reference_urls(value: Option<&Value>) -> Option<Vec<String>> {
    let refs_value = match value? {
        Value::Object(obj) => obj.get("referenceData"),
        other => Some(other),
    }?;
    let Value::Array(items) = refs_value else {
        return None;
    };
    let mut refs = Vec::new();
    for item in items {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let url = obj
            .get("url")
            .and_then(Value::as_str)
            .or_else(|| obj.get("href").and_then(Value::as_str))
            .or_else(|| obj.get("source").and_then(Value::as_str));
        if let Some(url) = url {
            if !refs.iter().any(|existing| existing == url) {
                refs.push(url.to_string());
            }
        }
    }
    if refs.is_empty() {
        None
    } else {
        Some(refs)
    }
}

/// Extract weakness identifiers or descriptions from SCAP weakness structures.
fn extract_weaknesses(
    weaknesses: Option<&Value>,
    problemtype: Option<&Value>,
) -> Option<Vec<String>> {
    let mut values = Vec::new();
    if let Some(Value::Array(items)) = weaknesses {
        for item in items {
            let Some(obj) = item.as_object() else {
                continue;
            };
            if let Some(Value::Array(descriptions)) = obj.get("description") {
                for description in descriptions {
                    if let Some(value) = description.get("value").and_then(Value::as_str) {
                        if !values.iter().any(|existing| existing == value) {
                            values.push(value.to_string());
                        }
                    }
                }
            }
        }
    }
    if let Some(Value::Object(problemtype_obj)) = problemtype {
        if let Some(Value::Array(items)) = problemtype_obj.get("problemtype_data") {
            for item in items {
                let Some(obj) = item.as_object() else {
                    continue;
                };
                if let Some(Value::Array(descriptions)) = obj.get("description") {
                    for description in descriptions {
                        if let Some(value) = description.get("value").and_then(Value::as_str) {
                            if !values.iter().any(|existing| existing == value) {
                                values.push(value.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

/// Extract normalized CVSS details from SCAP metrics or legacy impact blocks.
fn extract_cvss(metrics: Option<&Value>, impact: Option<&Value>) -> Option<Map<String, Value>> {
    let mut selected = Map::new();
    if let Some(Value::Object(metrics_obj)) = metrics {
        // NVD-style payloads may include multiple CVSS versions at once; keep the structured
        // blocks intact so downstream consumers can choose the representation they need.
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
            if let Some(value) = metrics_obj.get(key) {
                selected.insert(key.to_string(), value.clone());
            }
        }
    }
    if let Some(Value::Object(impact_obj)) = impact {
        for key in ["baseMetricV3", "baseMetricV2"] {
            if let Some(value) = impact_obj.get(key) {
                selected.insert(key.to_string(), value.clone());
            }
        }
    }
    if selected.is_empty() {
        None
    } else {
        Some(selected)
    }
}

/// Recursively collect affected CPE strings from nested SCAP configuration trees.
fn extract_affected_cpes(value: Option<&Value>) -> Option<Vec<String>> {
    let mut cpes = Vec::new();
    visit(value?, &mut cpes);
    if cpes.is_empty() {
        None
    } else {
        Some(cpes.into_iter().take(50).collect())
    }
}

/// Walk nested configuration trees and append any `cpe23Uri` strings encountered.
fn visit(value: &Value, cpes: &mut Vec<String>) {
    match value {
        Value::Object(obj) => {
            if obj.get("vulnerable") == Some(&Value::Bool(true)) {
                if let Some(cpe) = obj
                    .get("criteria")
                    .and_then(Value::as_str)
                    .or_else(|| obj.get("cpe23Uri").and_then(Value::as_str))
                {
                    if !cpes.iter().any(|existing| existing == cpe) {
                        cpes.push(cpe.to_string());
                    }
                }
            }
            // Nodes and children may be nested several levels deep, so recurse through every
            // object value instead of assuming a fixed SCAP schema depth.
            for nested in obj.values() {
                visit(nested, cpes);
            }
        }
        Value::Array(items) => {
            for item in items {
                visit(item, cpes);
            }
        }
        _ => {}
    }
}

/// Enrich a list of already-loaded result objects using the provided metadata indexes.
fn enrich_results(
    results: Vec<Map<String, Value>>,
    vt_index: Option<&HashMap<String, Value>>,
    notus_index: Option<&HashMap<String, Vec<Value>>>,
    scap_index: Option<&HashMap<String, Value>>,
) -> Vec<Value> {
    results
        .into_iter()
        .map(|result| enrich_one_result(result, vt_index, notus_index, scap_index))
        .collect()
}

/// Enrich a single result object with VT, Notus, and optional SCAP metadata.
fn enrich_one_result(
    mut result: Map<String, Value>,
    vt_index: Option<&HashMap<String, Value>>,
    notus_index: Option<&HashMap<String, Vec<Value>>>,
    scap_index: Option<&HashMap<String, Value>>,
) -> Value {
    let oid = extract_result_oid(&result);
    let vt_entry = oid
        .as_ref()
        .and_then(|value| vt_index.and_then(|index| index.get(value)).cloned());
    let notus_entries = oid
        .as_ref()
        .and_then(|value| notus_index.and_then(|index| index.get(value)).cloned())
        .unwrap_or_default();

    let vt_status = if oid.is_none() {
        "missing_oid"
    } else if vt_index.is_none() {
        "metadata_unavailable"
    } else if vt_entry.is_none() {
        "not_found"
    } else {
        "matched"
    };
    let notus_status = if oid.is_none() {
        "missing_oid"
    } else if notus_index.is_none() {
        "metadata_unavailable"
    } else if notus_entries.is_empty() {
        "not_found"
    } else {
        "matched"
    };

    let mut cve_ids = BTreeSet::new();
    if let Some(entry) = &vt_entry {
        for cve in extract_cve_ids_from_vt_metadata(entry) {
            cve_ids.insert(cve);
        }
    }
    for cve in extract_cve_ids_from_notus_metadata(&notus_entries) {
        cve_ids.insert(cve);
    }
    let cve_ids = cve_ids.into_iter().collect::<Vec<_>>();
    let cve_metadata = cve_ids
        .iter()
        .filter_map(|cve| scap_index.and_then(|index| index.get(cve)).cloned())
        .collect::<Vec<_>>();
    let cve_status = if cve_ids.is_empty() {
        "no_cves"
    } else if scap_index.is_none() {
        "metadata_unavailable"
    } else if cve_metadata.len() == cve_ids.len() {
        "matched"
    } else if !cve_metadata.is_empty() {
        "partial"
    } else {
        "not_found"
    };

    result.insert(
        "feed-metadata-source".to_string(),
        match (vt_entry.is_some(), !notus_entries.is_empty()) {
            (true, true) => Value::String("vt+notus".to_string()),
            (true, false) => Value::String("vt".to_string()),
            (false, true) => Value::String("notus".to_string()),
            (false, false) => Value::Null,
        },
    );
    result.insert(
        "vt-metadata-status".to_string(),
        Value::String(vt_status.to_string()),
    );
    result.insert("vt-metadata".to_string(), vt_entry.unwrap_or(Value::Null));
    result.insert(
        "notus-metadata-status".to_string(),
        Value::String(notus_status.to_string()),
    );
    result.insert("notus-metadata".to_string(), Value::Array(notus_entries));
    result.insert(
        "cve-ids".to_string(),
        Value::Array(cve_ids.into_iter().map(Value::String).collect()),
    );
    result.insert(
        "cve-metadata-status".to_string(),
        Value::String(cve_status.to_string()),
    );
    result.insert("cve-metadata".to_string(), Value::Array(cve_metadata));

    Value::Object(result)
}

/// Read JSON from plain text or gzip-compressed files.
fn read_json(path: &Path) -> Result<Value> {
    let data = fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    if path.extension().and_then(|value| value.to_str()) == Some("gz") {
        let mut decoder = GzDecoder::new(&data[..]);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded)?;
        Ok(serde_json::from_slice(&decoded)?)
    } else {
        Ok(serde_json::from_slice(&data)?)
    }
}
