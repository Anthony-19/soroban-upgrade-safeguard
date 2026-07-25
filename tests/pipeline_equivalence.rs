//! # Pipeline Equivalence Tests
//!
//! These tests assert that calling the library directly and running the CLI
//! binary produce **identical** reports for every fixture pair. They would
//! catch any regression where a pipeline stage (e.g. env-metadata comparison,
//! suppression) is added to one entry point but not the other.
//!
//! ## Acceptance criteria covered
//! - A test asserts the library and CLI produce identical reports for the same
//!   inputs across every fixture pair.
//! - That test fails if a stage is added to one path and not the other.

use serde_json::Value;
use soroban_upgrade_safeguard::{compare_wasm_files_with_options, CompareOptions};
use std::path::PathBuf;
use std::process::Command;

/// Resolve an absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Run the CLI binary on two WASM paths and parse its JSON output.
fn cli_report_json(old: &str, new: &str) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm(old))
        .arg(wasm(new))
        .args(["--format", "json"])
        .output()
        .expect("failed to spawn CLI binary");

    let stdout = String::from_utf8(output.stdout).expect("CLI stdout was not valid UTF-8");
    serde_json::from_str(&stdout).expect("CLI stdout was not valid JSON")
}

/// Call the library path and serialise its report to a JSON value.
fn lib_report_json(old: &str, new: &str) -> Value {
    let report =
        compare_wasm_files_with_options(&wasm(old), &wasm(new), &CompareOptions::default())
            .expect("library comparison should succeed on valid fixtures");

    serde_json::to_value(report.to_json()).expect("library report serialisation should succeed")
}

/// Assert that the two JSON reports are identical across the fields that the
/// canonical pipeline controls (findings, counts, safety flag).
///
/// Findings within each category are sorted by `target` before comparison so
/// that non-deterministic HashMap iteration order doesn't produce false failures.
///
/// We skip CLI-only decoration fields like `baseline_source` and
/// `verified_code_hash` which the CLI sets after the pipeline returns.
fn assert_equivalent(cli: &Value, lib: &Value, label: &str) {
    for field in &["is_safe", "counts"] {
        assert_eq!(
            cli[field], lib[field],
            "Fixture {label}: field '{field}' differs between CLI and library.\n\
             CLI: {cli}\n\
             Library: {lib}",
        );
    }

    // Compare findings_by_category after normalising ordering within each group.
    let cli_cats = normalise_findings(&cli["findings_by_category"]);
    let lib_cats = normalise_findings(&lib["findings_by_category"]);
    assert_eq!(
        cli_cats, lib_cats,
        "Fixture {label}: 'findings_by_category' differs between CLI and library.\n\
         CLI (normalised):     {cli_cats:?}\n\
         Library (normalised): {lib_cats:?}",
    );
}

/// Sort the findings within every category by their `target` field so that
/// HashMap iteration order doesn't affect equality assertions.
fn normalise_findings(findings_by_category: &Value) -> serde_json::Map<String, Value> {
    let mut result = serde_json::Map::new();
    if let Some(obj) = findings_by_category.as_object() {
        for (category, findings) in obj {
            let mut arr: Vec<Value> = findings.as_array().cloned().unwrap_or_default();
            arr.sort_by(|a, b| {
                let ta = a["target"].as_str().unwrap_or("");
                let tb = b["target"].as_str().unwrap_or("");
                ta.cmp(tb)
            });
            result.insert(category.clone(), Value::Array(arr));
        }
    }
    result
}

#[test]
fn v1_to_v1_identical_upgrade() {
    let cli = cli_report_json("v1.wasm", "v1.wasm");
    let lib = lib_report_json("v1.wasm", "v1.wasm");
    assert_equivalent(&cli, &lib, "v1→v1");
}

#[test]
fn v1_to_v2_breaking_upgrade() {
    let cli = cli_report_json("v1.wasm", "v2.wasm");
    let lib = lib_report_json("v1.wasm", "v2.wasm");
    assert_equivalent(&cli, &lib, "v1→v2");
}

#[test]
fn v1_to_v3_upgrade() {
    let cli = cli_report_json("v1.wasm", "v3.wasm");
    let lib = lib_report_json("v1.wasm", "v3.wasm");
    assert_equivalent(&cli, &lib, "v1→v3");
}

#[test]
fn v2_to_v3_upgrade() {
    let cli = cli_report_json("v2.wasm", "v3.wasm");
    let lib = lib_report_json("v2.wasm", "v3.wasm");
    assert_equivalent(&cli, &lib, "v2→v3");
}

/// Verify that the library now includes environment metadata findings, which
/// it was missing before the canonical pipeline was introduced.
///
/// This is the regression-guard test for the core of issue #72: environment
/// metadata comparison was CLI-only before this fix.
#[test]
fn library_includes_environment_metadata_findings() {
    // v1 and v3 share the same spec but may differ in env metadata.
    // We check that whatever the CLI reports for Environment, the library does too.
    let cli = cli_report_json("v1.wasm", "v3.wasm");
    let lib = lib_report_json("v1.wasm", "v3.wasm");

    let cli_env = &cli["findings_by_category"]["Environment"];
    let lib_env = &lib["findings_by_category"]["Environment"];

    assert_eq!(
        cli_env, lib_env,
        "Environment findings must be identical between CLI and library.\n\
         CLI: {cli_env}\n\
         Library: {lib_env}",
    );
}

/// Verify that both entry points agree on identical contracts producing no
/// environment findings, even when env metadata sections are present.
#[test]
fn identical_fixtures_produce_no_environment_findings_from_library() {
    let report = compare_wasm_files_with_options(
        &wasm("v1.wasm"),
        &wasm("v1.wasm"),
        &CompareOptions::default(),
    )
    .expect("should succeed");

    assert!(
        !report.findings_by_category.contains_key("Environment"),
        "Identical contracts must not produce Environment findings from the library; \
         got: {:?}",
        report.findings_by_category.get("Environment"),
    );
}
