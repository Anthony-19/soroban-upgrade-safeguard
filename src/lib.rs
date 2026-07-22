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
pub mod limits;
pub mod loader;
pub mod mapper;
pub mod parser;
pub mod report;
pub mod spec;
pub mod suppression;

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

    let old_spec = ContractSpec::from_entries(&old_meta.spec);
    let new_spec = ContractSpec::from_entries(&new_meta.spec);

    let old_spec_summary = old_spec.summary();
    let new_spec_summary = new_spec.summary();

    let mut diff_report = diff::compare_with_policy(&old_spec, &new_spec, policy)?;
    diff::compare_env_metadata(
        old_meta.env_meta.as_ref(),
        new_meta.env_meta.as_ref(),
        &mut diff_report,
    );

    let mut safety_report = report::SafetyReport::with_suppressions(
        &diff_report,
        suppressions,
        options.explain,
        options.strict,
    );
    safety_report.old_spec_summary = Some(old_spec_summary);
    safety_report.new_spec_summary = Some(new_spec_summary);

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
