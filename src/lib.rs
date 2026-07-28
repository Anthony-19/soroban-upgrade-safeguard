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

pub mod baseline;
pub mod builder;
pub mod classification;
pub mod color;
pub mod config;
pub mod dependency;
pub mod diff;
pub mod limits;
pub mod loader;
pub mod mapper;
pub mod parser;
pub mod rename;
pub mod report;
pub mod rules;
pub mod severity_override;
pub mod spec;
pub mod spec_input;
pub mod storage_schema;
pub mod suppression;
pub mod type_diff;
pub mod wasm_cache;

use std::path::Path;

use anyhow::{Context, Result};

use crate::report::SafetyReport;
use crate::spec::ContractSpec;
use crate::suppression::SuppressionConfig;

pub use crate::limits::{LimitError, ResourcePolicy};

/// Options for the canonical analysis pipeline.
///
/// Pass to [`compare_wasm_bytes_with_options`] or
/// [`compare_wasm_files_with_options`] to control suppression, resource limits,
/// explain output, and strict mode.
///
/// # Suppression
///
/// By default (`suppressions: None`) no suppression rules are applied, matching
/// the previous behavior of [`compare_wasm_bytes`]. Supply a loaded
/// [`SuppressionConfig`] to have the pipeline apply team-reviewed
/// acknowledgements, exactly as the CLI does with `.safeguard.toml`.
///
/// # Example — library caller with a suppression file
///
/// ```no_run
/// use std::path::Path;
/// use soroban_upgrade_safeguard::{CompareOptions, compare_wasm_files_with_options};
/// use soroban_upgrade_safeguard::suppression::SuppressionConfig;
///
/// let suppressions = SuppressionConfig::load_from_path(Path::new(".safeguard.toml"))?;
/// let report = compare_wasm_files_with_options(
///     Path::new("./v1.wasm"),
///     Path::new("./v2.wasm"),
///     &CompareOptions {
///         suppressions: Some(&suppressions),
///         ..Default::default()
///     },
/// )?;
/// # Ok::<(), anyhow::Error>(())
/// ```
#[derive(Default)]
pub struct CompareOptions<'a> {
    /// Resource limits for XDR decoding and type-walk operations.
    /// Defaults to [`ResourcePolicy::default`].
    pub policy: Option<&'a ResourcePolicy>,
    /// Suppression config to apply to findings.
    /// `None` means no suppressions are applied.
    pub suppressions: Option<&'a SuppressionConfig>,
    /// Include remediation guidance in each finding.
    pub explain: bool,
    /// Treat `Warning`-severity findings as failures (strict mode).
    pub strict: bool,
    /// When `true`, identical duplicate spec entries (same name, byte-identical
    /// definition) are downgraded to `Info` instead of failing the run.
    /// Conflicting duplicates (different definitions) always remain `Critical`
    /// even in compat mode — the analysis cannot be trusted when two definitions
    /// disagree, regardless of this flag.
    pub compat_duplicates: bool,
    /// Declared storage layouts of the old and new builds. When supplied, the
    /// pipeline additionally diffs these internal storage types through the same
    /// engine and records that storage was analyzed in the report's scope.
    ///
    /// Both sides are required together: a storage layout change is only
    /// observable as a difference between two snapshots. `None` (the default)
    /// leaves storage layout unanalyzed and the scope says so plainly.
    pub storage_schemas: Option<(
        &'a storage_schema::StorageSchema,
        &'a storage_schema::StorageSchema,
    )>,
}

/// Compare two Soroban contract builds supplied as raw WASM byte slices.
///
/// This runs the full analysis pipeline — metadata extraction, spec building,
/// structural diffing, cascade detection, **and environment-metadata
/// comparison** — and returns an aggregated [`SafetyReport`].
///
/// No suppression rules are applied; findings from `.safeguard.toml` files
/// are not loaded automatically. Use [`compare_wasm_bytes_with_options`] to
/// supply a [`SuppressionConfig`] explicitly.
///
/// Use [`compare_wasm_files`] to read the builds from disk.
///
/// `old_wasm` is the currently deployed (on-chain) contract and `new_wasm` is
/// the candidate upgrade.
///
/// # Errors
///
/// Returns an error if either input is not a parseable WASM module or if the
/// embedded `contractspecv0` section cannot be decoded.
pub fn compare_wasm_bytes(old_wasm: &[u8], new_wasm: &[u8]) -> Result<SafetyReport> {
    compare_wasm_bytes_with_options(old_wasm, new_wasm, &CompareOptions::default())
}

/// Like [`compare_wasm_bytes`], but bounds decoding and every recursive type walk
/// by an explicit [`ResourcePolicy`].
///
/// Untrusted WASM (a file, or bytes fetched over RPC) can declare oversized XDR
/// lengths or arbitrarily nested types. Threading `policy` through metadata
/// extraction and the diff makes those inputs fail with a controlled
/// [`LimitError`] instead of exhausting memory or overflowing the stack.
///
/// # Errors
///
/// Returns a [`LimitError`] (recoverable via [`anyhow::Error::downcast_ref`]) when
/// the input exceeds a configured limit, or an ordinary error if either input is
/// not a parseable WASM module or its `contractspecv0` section cannot be decoded.
pub fn compare_wasm_bytes_with_policy(
    old_wasm: &[u8],
    new_wasm: &[u8],
    policy: &ResourcePolicy,
) -> Result<SafetyReport> {
    compare_wasm_bytes_with_options(
        old_wasm,
        new_wasm,
        &CompareOptions {
            policy: Some(policy),
            ..Default::default()
        },
    )
}

/// The single canonical analysis pipeline.
///
/// This is the function that both the CLI and all library helpers ultimately
/// call. It runs every stage in the correct order:
///
/// 1. Metadata extraction and spec building for both contracts.
/// 2. Structural compatibility diff (functions, structs, enums, unions, cascade
///    detection).
/// 3. Environment metadata comparison (protocol interface version, etc.).
/// 4. Suppression application (if a [`SuppressionConfig`] is supplied via
///    `options`).
///
/// Adding a new pipeline stage requires only one change here; the CLI and
/// every library consumer automatically pick it up.
///
/// # Errors
///
/// Returns an error if either input is not a parseable WASM module, if the
/// embedded `contractspecv0` section cannot be decoded, or if a resource limit
/// from `options.policy` is exceeded.
pub fn compare_wasm_bytes_with_options(
    old_wasm: &[u8],
    new_wasm: &[u8],
    options: &CompareOptions<'_>,
) -> Result<SafetyReport> {
    let default_policy = ResourcePolicy::default();
    let policy = options.policy.unwrap_or(&default_policy);

    let empty_suppressions = SuppressionConfig::default();
    let suppressions = options.suppressions.unwrap_or(&empty_suppressions);

    let old_meta = parser::extract_metadata_with_policy(old_wasm, policy)
        .context("Failed to extract metadata from the old WASM")?;
    let new_meta = parser::extract_metadata_with_policy(new_wasm, policy)
        .context("Failed to extract metadata from the new WASM")?;

    // Build specs with duplicate detection. Conflicting duplicates are wired
    // into the diff report as Critical findings so they affect the exit code
    // and appear in JSON output; identical duplicates become Info findings.
    let (old_spec, old_dups) = ContractSpec::from_entries_checked(&old_meta.spec);
    let (new_spec, new_dups) = ContractSpec::from_entries_checked(&new_meta.spec);

    let old_spec_summary = old_spec.summary();
    let new_spec_summary = new_spec.summary();

    let mut diff_report = diff::compare_with_policy(&old_spec, &new_spec, policy)?;

    // Inject duplicate findings before the structural diff so that the report
    // presents them alongside the regular findings in JSON/text/markdown.
    diff::report_duplicate_spec_entries(
        "old",
        &old_dups,
        old_meta.spec_section_count,
        &mut diff_report,
        options.compat_duplicates,
    );
    diff::report_duplicate_spec_entries(
        "new",
        &new_dups,
        new_meta.spec_section_count,
        &mut diff_report,
        options.compat_duplicates,
    );

    diff::compare_env_metadata(
        old_meta.env_meta.as_ref(),
        new_meta.env_meta.as_ref(),
        &mut diff_report,
    );

    diff::compare_contract_metadata(
        old_meta.meta.as_ref(),
        new_meta.meta.as_ref(),
        &mut diff_report,
    );
    // Compare exported function names from the binary export sections.
    // This catches a removed export that callers depend on, and also any
    // mismatch between what the binary actually exports and what its spec claims.
    diff::compare_exports(
        &old_meta.exported_function_names,
        &new_meta.exported_function_names,
        &old_spec.functions.keys().cloned().collect(),
        &new_spec.functions.keys().cloned().collect(),
        &mut diff_report,
    );

    diff::compare_wasm_imports(&old_meta.imports, &new_meta.imports, &mut diff_report);

    // The pipeline always compares the exported interface and environment
    // metadata; storage layout is analyzed only when a schema is supplied for
    // both builds. The scope records which of those actually held so the verdict
    // is never read as broader than the analysis behind it.
    let mut scope = report::AnalysisScope {
        exported_interface: true,
        env_metadata: true,
        wasm_exports_compared: true,
        wasm_imports_compared: true,
        storage_schema: report::StorageScopeState::NotAnalyzed,
        old_spec_section_count: old_meta.spec_section_count,
        new_spec_section_count: new_meta.spec_section_count,
        old_duplicate_names: {
            let mut names: Vec<String> = old_dups.iter().map(|d| d.name.clone()).collect();
            names.sort();
            names.dedup();
            names
        },
        new_duplicate_names: {
            let mut names: Vec<String> = new_dups.iter().map(|d| d.name.clone()).collect();
            names.sort();
            names.dedup();
            names
        },
    };

    if let Some((old_schema, new_schema)) = options.storage_schemas {
        // A manifest that contradicts its own build is more dangerous than no
        // manifest, so disagreement stops the run rather than being reported.
        old_schema.reconcile_with_spec(&old_spec, "old")?;
        new_schema.reconcile_with_spec(&new_spec, "new")?;

        let old_resolved = old_schema.resolve()?;
        let new_resolved = new_schema.resolve()?;

        let storage_findings = diff::compare_storage_schemas(&old_resolved, &new_resolved);
        diff_report.findings.extend(storage_findings.findings);

        // Any reference the schema could not resolve is a coverage gap, surfaced
        // rather than silently absorbed into the verdict.
        let mut unresolved = old_schema.unresolved_references(Some(&old_spec));
        unresolved.extend(new_schema.unresolved_references(Some(&new_spec)));
        unresolved.sort();
        unresolved.dedup();
        diff::report_unresolved_storage_references(&unresolved, &mut diff_report);

        scope.storage_schema = report::StorageScopeState::Analyzed {
            key_types: new_resolved.key_type_count(),
            value_types: new_resolved.value_type_count(),
        };
    }

    let mut safety_report = report::SafetyReport::with_suppressions(
        &diff_report,
        suppressions,
        options.explain,
        options.strict,
        policy,
    );
    safety_report.old_spec_summary = Some(old_spec_summary);
    safety_report.new_spec_summary = Some(new_spec_summary);
    safety_report.scope = scope;

    // Populate build metrics so all output formats can report size and
    // interface-count deltas without the caller needing to extract them.
    safety_report.metrics = Some(report::BuildMetrics::new(
        old_wasm.len(),
        new_wasm.len(),
        old_spec.functions.len(),
        new_spec.functions.len(),
        old_spec.structs.len(),
        new_spec.structs.len(),
        old_spec.enums.len(),
        new_spec.enums.len(),
        old_spec.unions.len(),
        new_spec.unions.len(),
        old_spec.error_enums.len(),
        new_spec.error_enums.len(),
    ));

    Ok(safety_report)
}

/// Compare two Soroban contract builds read from WASM files on disk.
///
/// The files are validated as WASM binaries (via [`loader::load_wasm`]) before
/// being analyzed. No suppression rules are applied automatically.
/// Use [`compare_wasm_files_with_options`] to supply a [`SuppressionConfig`].
///
/// `old_path` points at the currently deployed (on-chain) contract and
/// `new_path` at the candidate upgrade.
///
/// # Errors
///
/// Returns an error if either file is missing, is not a valid WASM binary, or
/// if its embedded contract spec cannot be decoded.
pub fn compare_wasm_files(old_path: &Path, new_path: &Path) -> Result<SafetyReport> {
    compare_wasm_files_with_options(old_path, new_path, &CompareOptions::default())
}

/// Like [`compare_wasm_files`], but bounds decoding and every recursive type walk
/// by an explicit [`ResourcePolicy`]. See [`compare_wasm_bytes_with_policy`].
pub fn compare_wasm_files_with_policy(
    old_path: &Path,
    new_path: &Path,
    policy: &ResourcePolicy,
) -> Result<SafetyReport> {
    compare_wasm_files_with_options(
        old_path,
        new_path,
        &CompareOptions {
            policy: Some(policy),
            ..Default::default()
        },
    )
}

/// Like [`compare_wasm_files`], but accepts the full set of pipeline options.
///
/// Loads both WASM files from disk and delegates to [`compare_wasm_bytes_with_options`].
///
/// # Errors
///
/// Returns an error if either file is missing, is not a valid WASM binary,
/// if the embedded contract spec cannot be decoded, or if a resource limit
/// from `options.policy` is exceeded.
pub fn compare_wasm_files_with_options(
    old_path: &Path,
    new_path: &Path,
    options: &CompareOptions<'_>,
) -> Result<SafetyReport> {
    let old = loader::load_wasm(old_path)?;
    let new = loader::load_wasm(new_path)?;
    compare_wasm_bytes_with_options(&old.bytes, &new.bytes, options)
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
    compare_wasm_bytes_with_options(
        old_wasm,
        new_wasm,
        &CompareOptions {
            storage_schemas: Some((old_schema, new_schema)),
            ..Default::default()
        },
    )
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
    let old_schema = storage_schema::StorageSchema::load_from_path(old_schema_path)?;
    let new_schema = storage_schema::StorageSchema::load_from_path(new_schema_path)?;
    compare_wasm_files_with_options(
        old_path,
        new_path,
        &CompareOptions {
            storage_schemas: Some((&old_schema, &new_schema)),
            ..Default::default()
        },
    )
}

/// Run the full analysis pipeline starting from pre-extracted [`parser::SorobanMetadata`].
///
/// This is the variant the CLI uses when one or both sides is a spec-only JSON
/// file (via `--old-spec` / `--new-spec`): spec loading happens before this
/// call, so the WASM bytes are not available here. When both sides are WASM
/// files the caller should prefer [`compare_wasm_bytes_with_options`] instead.
///
/// `wasm_sizes` carries `(old_bytes, new_bytes)` for the build-metrics block.
/// Pass `None` when byte sizes are unavailable (spec-only on both sides).
///
/// # Errors
///
/// Returns an error if either metadata cannot be decoded into a valid spec, if
/// the structural diff exceeds a resource limit from `options.policy`, or if a
/// storage schema contradicts its associated spec.
pub fn run_pipeline_with_metadata(
    old_meta: parser::SorobanMetadata,
    new_meta: parser::SorobanMetadata,
    wasm_sizes: Option<(usize, usize)>,
    options: &CompareOptions<'_>,
) -> Result<SafetyReport> {
    let default_policy = ResourcePolicy::default();
    let policy = options.policy.unwrap_or(&default_policy);

    let empty_suppressions = SuppressionConfig::default();
    let suppressions = options.suppressions.unwrap_or(&empty_suppressions);

    // Determine whether the inputs were real WASM (exports/imports comparable)
    // or spec-only JSON (no binary sections).
    let (old_size, new_size) = wasm_sizes.unwrap_or((0, 0));
    let is_wasm = wasm_sizes.is_some();

    let (old_spec, old_dups) = ContractSpec::from_entries_checked(&old_meta.spec);
    let (new_spec, new_dups) = ContractSpec::from_entries_checked(&new_meta.spec);

    let old_spec_summary = old_spec.summary();
    let new_spec_summary = new_spec.summary();

    let mut diff_report = diff::compare_with_policy(&old_spec, &new_spec, policy)?;

    diff::report_duplicate_spec_entries(
        "old",
        &old_dups,
        old_meta.spec_section_count,
        &mut diff_report,
        options.compat_duplicates,
    );
    diff::report_duplicate_spec_entries(
        "new",
        &new_dups,
        new_meta.spec_section_count,
        &mut diff_report,
        options.compat_duplicates,
    );

    diff::compare_env_metadata(
        old_meta.env_meta.as_ref(),
        new_meta.env_meta.as_ref(),
        &mut diff_report,
    );

    diff::compare_contract_metadata(
        old_meta.meta.as_ref(),
        new_meta.meta.as_ref(),
        &mut diff_report,
    );

    if is_wasm {
        diff::compare_exports(
            &old_meta.exported_function_names,
            &new_meta.exported_function_names,
            &old_spec.functions.keys().cloned().collect(),
            &new_spec.functions.keys().cloned().collect(),
            &mut diff_report,
        );
        diff::compare_wasm_imports(&old_meta.imports, &new_meta.imports, &mut diff_report);
    }

    let mut scope = report::AnalysisScope {
        exported_interface: true,
        env_metadata: true,
        wasm_exports_compared: is_wasm,
        wasm_imports_compared: is_wasm,
        storage_schema: report::StorageScopeState::NotAnalyzed,
        old_spec_section_count: old_meta.spec_section_count,
        new_spec_section_count: new_meta.spec_section_count,
        old_duplicate_names: {
            let mut names: Vec<String> = old_dups.iter().map(|d| d.name.clone()).collect();
            names.sort();
            names.dedup();
            names
        },
        new_duplicate_names: {
            let mut names: Vec<String> = new_dups.iter().map(|d| d.name.clone()).collect();
            names.sort();
            names.dedup();
            names
        },
    };

    if let Some((old_schema, new_schema)) = options.storage_schemas {
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

        scope.storage_schema = report::StorageScopeState::Analyzed {
            key_types: new_resolved.key_type_count(),
            value_types: new_resolved.value_type_count(),
        };
    }

    let mut safety_report = report::SafetyReport::with_suppressions(
        &diff_report,
        suppressions,
        options.explain,
        options.strict,
        policy,
    );
    safety_report.old_spec_summary = Some(old_spec_summary);
    safety_report.new_spec_summary = Some(new_spec_summary);
    safety_report.scope = scope;

    safety_report.metrics = Some(report::BuildMetrics::new(
        old_size,
        new_size,
        old_spec.functions.len(),
        new_spec.functions.len(),
        old_spec.structs.len(),
        new_spec.structs.len(),
        old_spec.enums.len(),
        new_spec.enums.len(),
        old_spec.unions.len(),
        new_spec.unions.len(),
        old_spec.error_enums.len(),
        new_spec.error_enums.len(),
    ));

    Ok(safety_report)
}
