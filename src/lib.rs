//! # Soroban Upgrade Safeguard
//!
//! Library for analyzing and validating Soroban smart-contract upgrades on the
//! Stellar network. It detects breaking changes in storage layout, function
//! signatures, and event schemas before an upgrade is deployed.
//!
//! The crate is split into focused modules that form an analysis pipeline:
//!
//! - [`loader`] reads and validates raw WASM binaries from disk.
//! - [`parser`] extracts the Soroban `contractspecv0` custom section and decodes
//!   its XDR entries.
//! - [`spec`] organizes the decoded entries into a [`spec::ContractSpec`].
//! - [`mapper`] builds type-dependency graphs used for cascade detection.
//! - [`diff`] compares two specs and produces a list of findings.
//! - [`report`] aggregates findings into a [`report::SafetyReport`].
//!
//! The exported spec only describes a contract's *callable surface*. Storage
//! compatibility is governed by internal storage-key and value types that need
//! not appear in it at all, so [`storage_schema`] defines an opt-in manifest in
//! which a team declares those types for analysis.
//!
//! Most callers only need the two top-level helpers, [`compare_wasm_files`] and
//! [`compare_wasm_bytes`], which run the whole pipeline and return a structured
//! [`report::SafetyReport`]. The individual modules are public so that more
//! specialized tools (CI bots, dashboards, custom checks) can reuse any single
//! stage without shelling out to the CLI binary.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//!
//! let report = soroban_upgrade_safeguard::compare_wasm_files(
//!     Path::new("./wasm/v1.wasm"),
//!     Path::new("./wasm/v2.wasm"),
//! )?;
//!
//! if !report.is_safe {
//!     eprintln!("Upgrade is unsafe: {} critical issue(s)", report.critical_count);
//! }
//! # Ok::<(), anyhow::Error>(())
//! ```

pub mod color;
pub mod diff;
pub mod loader;
pub mod mapper;
pub mod parser;
pub mod report;
pub mod spec;
pub mod storage_schema;
pub mod suppression;

use std::path::Path;

use anyhow::{Context, Result};

use crate::report::SafetyReport;
use crate::spec::ContractSpec;

/// Compare two Soroban contract builds supplied as raw WASM byte slices.
///
/// This runs the full analysis pipeline — metadata extraction, spec building,
/// structural diffing, and cascade detection — and returns an aggregated
/// [`SafetyReport`]. Use this overload when the WASM is already in memory (for
/// example fetched over the network); use [`compare_wasm_files`] to read the
/// builds from disk.
///
/// `old_wasm` is the currently deployed (on-chain) contract and `new_wasm` is
/// the candidate upgrade.
///
/// # Errors
///
/// Returns an error if either input is not a parseable WASM module or if the
/// embedded `contractspecv0` section cannot be decoded.
pub fn compare_wasm_bytes(old_wasm: &[u8], new_wasm: &[u8]) -> Result<SafetyReport> {
    let old_meta = parser::extract_metadata(old_wasm)
        .context("Failed to extract metadata from the old WASM")?;
    let new_meta = parser::extract_metadata(new_wasm)
        .context("Failed to extract metadata from the new WASM")?;

    let old_spec = ContractSpec::from_entries(&old_meta.spec);
    let new_spec = ContractSpec::from_entries(&new_meta.spec);

    let diff_report = diff::compare(&old_spec, &new_spec);
    Ok(SafetyReport::new(&diff_report))
}

/// Compare two Soroban contract builds read from WASM files on disk.
///
/// The files are validated as WASM binaries (via [`loader::load_wasm`]) before
/// being analyzed. This is the path used by the CLI binary and is the most
/// convenient entry point for callers that have the builds on disk.
///
/// `old_path` points at the currently deployed (on-chain) contract and
/// `new_path` at the candidate upgrade.
///
/// # Errors
///
/// Returns an error if either file is missing, is not a valid WASM binary, or
/// if its embedded contract spec cannot be decoded.
pub fn compare_wasm_files(old_path: &Path, new_path: &Path) -> Result<SafetyReport> {
    let old = loader::load_wasm(old_path)?;
    let new = loader::load_wasm(new_path)?;
    compare_wasm_bytes(&old.bytes, &new.bytes)
}

/// Compare two builds *and* their declared storage layouts.
///
/// [`compare_wasm_bytes`] only sees the exported interface, so its report
/// certifies nothing about storage. This overload additionally diffs the storage
/// types each build declares, through the same engine and severities, and the
/// returned report's [`report::AnalysisScope`] records that storage was actually
/// analyzed.
///
/// Both schemas are required: a storage layout change is only observable as a
/// difference between two snapshots.
///
/// # Errors
///
/// Returns an error if either WASM cannot be parsed, or if either schema
/// contradicts its own build's exported spec. A manifest that disagrees with the
/// contract is rejected rather than trusted, since acting on a wrong declaration
/// is worse than having none.
pub fn compare_wasm_bytes_with_storage_schemas(
    old_wasm: &[u8],
    new_wasm: &[u8],
    old_schema: &storage_schema::StorageSchema,
    new_schema: &storage_schema::StorageSchema,
) -> Result<SafetyReport> {
    let old_meta = parser::extract_metadata(old_wasm)
        .context("Failed to extract metadata from the old WASM")?;
    let new_meta = parser::extract_metadata(new_wasm)
        .context("Failed to extract metadata from the new WASM")?;

    let old_spec = ContractSpec::from_entries(&old_meta.spec);
    let new_spec = ContractSpec::from_entries(&new_meta.spec);

    let mut diff_report = diff::compare(&old_spec, &new_spec);
    diff::compare_env_metadata(
        old_meta.env_meta.as_ref(),
        new_meta.env_meta.as_ref(),
        &mut diff_report,
    );

    old_schema.reconcile_with_spec(&old_spec, "old")?;
    new_schema.reconcile_with_spec(&new_spec, "new")?;

    let old_resolved = old_schema.resolve()?;
    let new_resolved = new_schema.resolve()?;

    let storage_findings = diff::compare_storage_schemas(&old_resolved, &new_resolved);
    diff_report.findings.extend(storage_findings.findings);

    let mut unresolved = old_schema.unresolved_references(Some(&old_spec));
    unresolved.extend(new_schema.unresolved_references(Some(&new_spec)));
    unresolved.sort();
    unresolved.dedup();
    diff::report_unresolved_storage_references(&unresolved, &mut diff_report);

    let scope = report::AnalysisScope {
        exported_interface: true,
        env_metadata: true,
        storage_schema: report::StorageScopeState::Analyzed {
            key_types: new_resolved.key_type_count(),
            value_types: new_resolved.value_type_count(),
        },
    };

    Ok(SafetyReport::new(&diff_report).with_scope(scope))
}

/// Compare two builds on disk together with their storage-schema manifests.
///
/// See [`compare_wasm_bytes_with_storage_schemas`] for what this certifies.
///
/// # Errors
///
/// Returns an error if any of the four files is missing, unparseable, or if a
/// schema contradicts its build's exported spec.
pub fn compare_wasm_files_with_storage_schemas(
    old_path: &Path,
    new_path: &Path,
    old_schema_path: &Path,
    new_schema_path: &Path,
) -> Result<SafetyReport> {
    let old = loader::load_wasm(old_path)?;
    let new = loader::load_wasm(new_path)?;
    let old_schema = storage_schema::StorageSchema::load_from_path(old_schema_path)?;
    let new_schema = storage_schema::StorageSchema::load_from_path(new_schema_path)?;
    compare_wasm_bytes_with_storage_schemas(&old.bytes, &new.bytes, &old_schema, &new_schema)
}
