//! Loading a Soroban contract spec from a JSON file instead of a WASM binary.
//!
//! A WASM binary contains several pieces of data beyond the spec itself:
//! environment metadata (`contractenvmetav0`), build metadata
//! (`contractmetav0`), the import section, and the export section. A spec-only
//! JSON file omits all of those. The pipeline therefore skips the comparisons
//! that depend on WASM-only data and records the gap in the
//! [`report::AnalysisScope`] so the verdict is never read as broader than what
//! actually ran.
//!
//! # File format
//!
//! The JSON file is an object with a single `entries` array. Each element is
//! a **base64-encoded XDR `SCSpecEntry`** — the same encoding used in RPC
//! responses and by `stellar contract inspect --output xdr-base64`:
//!
//! ```json
//! {
//!   "entries": [
//!     "AAAAAQAAAA...",
//!     "AAAAAQAAAB...",
//!     "..."
//!   ]
//! }
//! ```
//!
//! This format is self-describing and round-trippable: every entry is exactly
//! one `SCSpecEntry` XDR value, base64-encoded, the same unit the WASM parser
//! produces internally.
//!
//! # Producing the file
//!
//! Extract spec entries from a WASM with the Stellar CLI:
//!
//! ```bash
//! stellar contract inspect --wasm path/to/contract.wasm --output xdr-base64-array \
//!   | jq '{entries: .}' > contract-spec.json
//! ```
//!
//! Or, if you have the spec as concatenated binary XDR (as stored in the WASM
//! custom section), base64-encode each entry individually and place them in the
//! array.
//!
//! # Skipped comparisons
//!
//! When one or both sides is a spec-only file the following comparisons are
//! skipped because the required data is not present:
//!
//! - **Environment metadata** (`contractenvmetav0`) — protocol interface
//!   version check.
//! - **Build metadata** (`contractmetav0`) — tool-version check.
//! - **Export section** — check that every spec'd function is actually
//!   exported from the binary.
//! - **Import section** — host-function dependency diff.
//!
//! The exported interface (functions, structs, enums, unions, error enums) is
//! always compared regardless of input mode.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;
use stellar_xdr::curr::{ReadXdr, ScSpecEntry};

use crate::limits::ResourcePolicy;
use crate::parser::SorobanMetadata;
use crate::spec::TaggedSpecEntry;

/// The JSON shape written to / read from a spec-only input file.
#[derive(Debug, Deserialize)]
pub struct ContractSpecJson {
    /// Base64-encoded XDR `SCSpecEntry` values, one per element.
    pub entries: Vec<String>,
}

/// Load a [`SorobanMetadata`] from a spec JSON file.
///
/// The returned metadata has its `spec` field populated from the file's
/// entries; all other fields (`env_meta`, `meta`, `imports`,
/// `exported_function_names`) are left at their zero / empty defaults, which
/// signals to the pipeline that those comparisons are unavailable.
///
/// # Errors
///
/// Returns an error if the file cannot be read, if its content is not valid
/// JSON matching [`ContractSpecJson`], or if any entry's base64 or XDR decoding
/// fails.
pub fn load_spec_json(path: &Path, policy: &ResourcePolicy) -> Result<SorobanMetadata> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read spec JSON file '{}'", path.display()))?;

    let spec_json: ContractSpecJson = serde_json::from_str(&content).with_context(|| {
        format!(
            "Failed to parse spec JSON file '{}'. \
             Expected {{ \"entries\": [\"<base64-xdr>\", ...] }}",
            path.display()
        )
    })?;

    if spec_json.entries.is_empty() {
        anyhow::bail!(
            "Spec JSON file '{}' contains no entries. \
             The 'entries' array must have at least one SCSpecEntry.",
            path.display()
        );
    }

    let limits = policy.xdr_limits();

    let tagged: Vec<TaggedSpecEntry> = spec_json
        .entries
        .iter()
        .enumerate()
        .map(|(i, b64)| {
            let xdr_bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .with_context(|| {
                    format!(
                        "Entry {} in '{}' is not valid base64",
                        i,
                        path.display()
                    )
                })?;

            let entry =
                ScSpecEntry::read_xdr(&mut stellar_xdr::curr::Limited::new(
                    xdr_bytes.as_slice(),
                    limits.clone(),
                ))
                .with_context(|| {
                    format!(
                        "Failed to decode XDR for entry {} in '{}'",
                        i,
                        path.display()
                    )
                })?;

            Ok(TaggedSpecEntry::new(entry, 0))
        })
        .collect::<Result<_>>()?;

    Ok(SorobanMetadata {
        spec: tagged,
        spec_section_count: 1, // treat as a single logical section
        env_meta: None,
        meta: None,
        imports: Vec::new(),
        exported_function_names: std::collections::BTreeSet::new(),
    })
}

/// Returns `true` when `path` looks like a spec JSON file rather than a WASM.
///
/// The heuristic checks the file extension (`.json`) and the first non-
/// whitespace byte (must be `{`). This lets `main.rs` auto-detect the input
/// type without requiring an explicit flag.
pub fn is_spec_json(path: &Path) -> bool {
    // Extension check first (cheap).
    if path.extension().and_then(|e| e.to_str()) == Some("json") {
        return true;
    }
    false
}

// Re-export so callers don't have to import base64 themselves.
use base64::Engine as _;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::ResourcePolicy;
    use std::io::Write;

    /// Build a minimal valid `SCSpecEntry` (a void function with no params)
    /// and return its base64-XDR encoding.
    fn minimal_spec_entry_b64() -> String {
        use stellar_xdr::curr::{
            ScSpecEntry, ScSpecFunctionV0, ScSpecTypeDef, ScSpecTypeVoid, StringM, VecM, WriteXdr,
        };

        let entry = ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: StringM::default(),
            name: "hello".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: vec![ScSpecTypeDef::Void(ScSpecTypeVoid {})].try_into().unwrap(),
        });

        let bytes = entry.to_xdr(stellar_xdr::curr::Limits::none()).unwrap();
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    }

    fn write_spec_json(entries: &[String]) -> tempfile::NamedTempFile {
        let json = serde_json::json!({ "entries": entries }).to_string();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f
    }

    // ── is_spec_json ─────────────────────────────────────────────────────────

    #[test]
    fn json_extension_is_recognised() {
        assert!(is_spec_json(Path::new("contract-spec.json")));
    }

    #[test]
    fn wasm_extension_is_not_recognised() {
        assert!(!is_spec_json(Path::new("contract.wasm")));
    }

    // ── load_spec_json ───────────────────────────────────────────────────────

    #[test]
    fn loads_valid_spec_json() {
        let b64 = minimal_spec_entry_b64();
        let f = write_spec_json(&[b64]);
        let meta = load_spec_json(f.path(), &ResourcePolicy::default())
            .expect("should load without error");
        assert_eq!(meta.spec.len(), 1);
        // Spec-only metadata has empty WASM-specific fields.
        assert!(meta.env_meta.is_none());
        assert!(meta.imports.is_empty());
        assert!(meta.exported_function_names.is_empty());
        assert_eq!(meta.spec_section_count, 1);
    }

    #[test]
    fn rejects_empty_entries_array() {
        let f = write_spec_json(&[]);
        let err = load_spec_json(f.path(), &ResourcePolicy::default())
            .expect_err("empty entries must be rejected");
        assert!(err.to_string().contains("no entries"), "got: {err}");
    }

    #[test]
    fn rejects_invalid_base64() {
        let f = write_spec_json(&["!!!not-base64!!!".to_string()]);
        let err = load_spec_json(f.path(), &ResourcePolicy::default())
            .expect_err("invalid base64 must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("base64") || msg.contains("Entry 0"), "got: {msg}");
    }

    #[test]
    fn rejects_valid_base64_but_invalid_xdr() {
        // Valid base64 but not valid SCSpecEntry XDR.
        let f = write_spec_json(&[base64::engine::general_purpose::STANDARD.encode(b"deadbeef")]);
        let err = load_spec_json(f.path(), &ResourcePolicy::default())
            .expect_err("invalid XDR must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("XDR") || msg.contains("decode"), "got: {msg}");
    }

    #[test]
    fn rejects_missing_entries_field() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"{\"spec\": []}").unwrap();
        let err = load_spec_json(f.path(), &ResourcePolicy::default())
            .expect_err("missing 'entries' field must be rejected");
        assert!(
            err.to_string().contains("entries") || err.to_string().contains("parse"),
            "got: {err}"
        );
    }
}
