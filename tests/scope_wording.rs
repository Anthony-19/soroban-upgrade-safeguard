//! Snapshot tests for the bounded-claim wording in every output format.
//!
//! The issue these guard against is not a crash but a sentence: a verdict that
//! reads as broader than the analysis behind it. The exact wording is therefore
//! part of the contract, and these tests pin it in text, JSON, and Markdown, for
//! both the storage-analyzed and storage-not-analyzed cases.

use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn schema(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("schemas")
        .join(name)
}

/// Run the binary and return (exit code, stdout).
fn run(args: &[&str]) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .arg("--no-color")
        .output()
        .expect("failed to run binary");
    (
        output.status.code().expect("process terminated by signal"),
        String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
    )
}

fn run_pair(old: &str, new: &str, extra: &[&str]) -> (i32, String) {
    let old_path = wasm(old);
    let new_path = wasm(new);
    let mut args = vec![old_path.to_str().unwrap(), new_path.to_str().unwrap()];
    args.extend_from_slice(extra);
    run(&args)
}

// ---------------------------------------------------------------------
// No storage schema: the claim must stay bounded to the exported interface
// ---------------------------------------------------------------------

/// The exact sentence that stops a green run from being read as
/// "storage-compatible". It must appear verbatim in every format.
const BOUNDED_CLAIM: &str = "Exported interface + environment metadata only — \
     storage layout is NOT verified by this result.";

const STORAGE_NOT_ANALYZED: &str = "Storage layout: NOT analyzed — no storage schema supplied.";

#[test]
fn text_passing_verdict_states_what_it_certifies() {
    let (code, stdout) = run_pair("v1.wasm", "v1.wasm", &[]);

    assert_eq!(code, 0);
    assert!(
        stdout.contains("Status: ✅ PASSED (No exported-interface breaking changes)"),
        "the pass must be scoped to the exported interface:\n{stdout}"
    );
    assert!(
        stdout.contains(BOUNDED_CLAIM),
        "the bounded claim must appear verbatim:\n{stdout}"
    );
    assert!(
        stdout.contains(STORAGE_NOT_ANALYZED),
        "an unanalyzed dimension must be stated, not omitted:\n{stdout}"
    );
    // The old, overclaiming vocabulary must be gone.
    assert!(
        !stdout.contains("PASSED (No breaking changes detected)"),
        "the unbounded verdict wording must not reappear"
    );
}

#[test]
fn text_failing_verdict_names_the_scope_that_broke() {
    let (code, stdout) = run_pair("v1.wasm", "v2.wasm", &[]);

    assert_eq!(code, 1);
    assert!(
        stdout.contains("Status: ❌ FAILED (Exported-interface breaking changes detected)"),
        "a failure must name the scope it came from:\n{stdout}"
    );
    assert!(stdout.contains(STORAGE_NOT_ANALYZED));
}

#[test]
fn markdown_states_the_bounded_claim() {
    let (_, stdout) = run_pair("v1.wasm", "v1.wasm", &["--format", "markdown"]);

    assert!(stdout.contains("## Status: ✅ PASSED (No exported-interface breaking changes)"));
    assert!(
        stdout.contains(&format!("_{BOUNDED_CLAIM}_")),
        "markdown must carry the bounded claim:\n{stdout}"
    );
    assert!(stdout.contains(&format!("**Scope:** {STORAGE_NOT_ANALYZED}")));
    assert!(
        stdout.contains("does NOT certify storage-layout compatibility"),
        "the no-changes path must still bound its claim:\n{stdout}"
    );
}

#[test]
fn json_exposes_scope_and_coverage() {
    let (_, stdout) = run_pair("v1.wasm", "v1.wasm", &["--format", "json"]);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    assert_eq!(json["is_safe"], serde_json::Value::Bool(true));
    assert_eq!(json["certifies"], BOUNDED_CLAIM);

    let scope = &json["scope"];
    assert_eq!(scope["exported_interface_analyzed"], true);
    assert_eq!(scope["env_metadata_analyzed"], true);
    assert_eq!(
        scope["storage_layout_analyzed"], false,
        "a machine consumer must be able to see storage was not analyzed"
    );
    assert!(
        scope["storage_key_types"].is_null(),
        "no counts are reported when nothing was analyzed"
    );
    assert_eq!(scope["summary"], BOUNDED_CLAIM);
}

// ---------------------------------------------------------------------
// With a storage schema: the claim widens, but only as far as the schema
// ---------------------------------------------------------------------

#[test]
fn text_widens_the_claim_when_a_schema_is_analyzed() {
    let (code, stdout) = run_pair(
        "v1.wasm",
        "v1.wasm",
        &[
            "--old-storage-schema",
            schema("lending_v1.toml").to_str().unwrap(),
            "--new-storage-schema",
            schema("lending_v1.toml").to_str().unwrap(),
        ],
    );

    assert_eq!(code, 0, "an unchanged declared layout passes");
    assert!(
        stdout.contains("Status: ✅ PASSED (No exported-interface or declared-storage breaks)"),
        "the pass may now speak to storage too:\n{stdout}"
    );
    assert!(
        stdout.contains(
            "Storage layout: analyzed against the declared schema \
             (1 key type(s), 1 value type(s))."
        ),
        "coverage must be quantified:\n{stdout}"
    );
    // Even widened, the claim stays bounded to what was declared.
    assert!(
        stdout.contains("Storage coverage is limited to the declared types."),
        "the widened claim must still bound itself:\n{stdout}"
    );
    assert!(!stdout.contains(STORAGE_NOT_ANALYZED));
}

#[test]
fn json_reports_storage_coverage_counts_when_a_schema_is_analyzed() {
    let (_, stdout) = run_pair(
        "v1.wasm",
        "v1.wasm",
        &[
            "--format",
            "json",
            "--old-storage-schema",
            schema("lending_v1.toml").to_str().unwrap(),
            "--new-storage-schema",
            schema("lending_v1.toml").to_str().unwrap(),
        ],
    );
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    let scope = &json["scope"];
    assert_eq!(scope["storage_layout_analyzed"], true);
    assert_eq!(scope["storage_key_types"], 1);
    assert_eq!(scope["storage_value_types"], 1);
    assert!(json["certifies"]
        .as_str()
        .unwrap()
        .contains("Storage coverage is limited to the declared types."));
}

#[test]
fn markdown_widens_the_claim_when_a_schema_is_analyzed() {
    let (_, stdout) = run_pair(
        "v1.wasm",
        "v1.wasm",
        &[
            "--format",
            "markdown",
            "--old-storage-schema",
            schema("lending_v1.toml").to_str().unwrap(),
            "--new-storage-schema",
            schema("lending_v1.toml").to_str().unwrap(),
        ],
    );

    assert!(
        stdout.contains("## Status: ✅ PASSED (No exported-interface or declared-storage breaks)"),
        "{stdout}"
    );
    assert!(stdout.contains("**Scope:** Storage layout: analyzed against the declared schema"));
}
