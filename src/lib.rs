pub mod color;
pub mod diff;
pub mod empirical;
pub mod error;
pub mod interface_hash;
pub mod loader;
pub mod mapper;
pub mod parser;
pub mod render;
pub mod report;
pub mod spec;
pub mod spec_json;
pub mod suppression;

use std::path::Path;

use anyhow::{Context, Result};

use crate::report::SafetyReport;
use crate::spec::ContractSpec;
use crate::suppression::SuppressionConfig;

/// Compare two Soroban contract builds supplied as raw WASM byte slices.
pub fn compare_wasm_bytes(old_wasm: &[u8], new_wasm: &[u8]) -> Result<SafetyReport> {
    let old_meta = parser::extract_metadata(old_wasm)
        .context("Failed to extract metadata from the old WASM")?;
    let new_meta = parser::extract_metadata(new_wasm)
        .context("Failed to extract metadata from the new WASM")?;

    let old_spec = ContractSpec::from_entries(&old_meta.spec);
    let new_spec = ContractSpec::from_entries(&new_meta.spec);

    let diff_report = diff::compare(&old_spec, &new_spec);
    Ok(SafetyReport::new(&diff_report)
        .with_interface_hashes(old_spec.interface_hash(), new_spec.interface_hash()))
}

/// Compare two Soroban contract builds read from WASM files on disk.
pub fn compare_wasm_files(old_path: &Path, new_path: &Path) -> Result<SafetyReport> {
    let old = loader::load_wasm(old_path).map_err(|e| anyhow::anyhow!("{}", e))?;
    let new = loader::load_wasm(new_path).map_err(|e| anyhow::anyhow!("{}", e))?;
    compare_wasm_bytes(&old.bytes, &new.bytes)
}

/// Options for the analysis pipeline.
#[derive(Default)]
pub struct CompareOptions<'a> {
    pub suppressions: Option<&'a SuppressionConfig>,
    pub explain: bool,
    pub strict: bool,
}

/// Compare two Soroban contract builds supplied as raw WASM byte slices with options.
pub fn compare_wasm_bytes_with_options(
    old_wasm: &[u8],
    new_wasm: &[u8],
    options: &CompareOptions<'_>,
) -> Result<SafetyReport> {
    let empty_suppressions = SuppressionConfig::default();
    let suppressions = options.suppressions.unwrap_or(&empty_suppressions);

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

    let mut safety_report = SafetyReport::with_suppressions(
        &diff_report,
        suppressions,
        options.explain,
        options.strict,
    );
    safety_report.old_spec_summary = Some(old_spec.summary());
    safety_report.new_spec_summary = Some(new_spec.summary());

    Ok(safety_report)
}

/// Compare two Soroban contract builds read from WASM files on disk with options.
pub fn compare_wasm_files_with_options(
    old_path: &Path,
    new_path: &Path,
    options: &CompareOptions<'_>,
) -> Result<SafetyReport> {
    let old = loader::load_wasm(old_path).map_err(|e| anyhow::anyhow!("{}", e))?;
    let new = loader::load_wasm(new_path).map_err(|e| anyhow::anyhow!("{}", e))?;
    compare_wasm_bytes_with_options(&old.bytes, &new.bytes, options)
}
