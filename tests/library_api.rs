//! Integration tests for the public library API.
//!
//! Unlike `json_output.rs`, these never spawn the CLI binary — they link the
//! library crate directly and call the top-level comparison helpers, proving
//! the core loading/parsing/diffing logic is reusable by external Rust tools.

use std::path::PathBuf;

use soroban_upgrade_safeguard::{compare_wasm_bytes, compare_wasm_files};

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn library_detects_breaking_upgrade_from_files() {
    let report = compare_wasm_files(&wasm("v1.wasm"), &wasm("v2.wasm"))
        .expect("comparison should succeed on valid fixtures");

    assert!(!report.is_safe, "v1 -> v2 must be flagged as unsafe");
    assert!(
        report.critical_count >= 1,
        "v1 -> v2 must report at least one critical finding"
    );
    assert_eq!(
        report.total_findings,
        report.critical_count + report.warning_count + report.info_count,
        "total findings must equal the sum of severity counts"
    );
}

#[test]
fn library_identical_upgrade_is_safe_from_files() {
    let report = compare_wasm_files(&wasm("v1.wasm"), &wasm("v1.wasm"))
        .expect("comparison should succeed on valid fixtures");

    assert!(report.is_safe, "identical builds must be safe");
    assert_eq!(
        report.critical_count, 0,
        "identical builds have no criticals"
    );
}

#[test]
fn library_compares_in_memory_bytes() {
    let old = std::fs::read(wasm("v1.wasm")).expect("read v1 fixture");
    let new = std::fs::read(wasm("v2.wasm")).expect("read v2 fixture");

    let report =
        compare_wasm_bytes(&old, &new).expect("comparison should succeed on in-memory bytes");

    assert!(!report.is_safe);
    assert!(report.critical_count >= 1);

    // The byte-slice and file-path entry points must agree.
    let from_files = compare_wasm_files(&wasm("v1.wasm"), &wasm("v2.wasm")).unwrap();
    assert_eq!(report.critical_count, from_files.critical_count);
    assert_eq!(report.total_findings, from_files.total_findings);
}

#[test]
fn test_duplicate_warning_stderr() {
    use stellar_xdr::curr::{ScSpecEntry, ScSpecFunctionV0, VecM};
    use soroban_upgrade_safeguard::spec::ContractSpec;

    // If a special env var is set, run the duplicate spec generation and panic.
    if std::env::var("RUN_DUPLICATE_SPEC_TEST").is_ok() {
        let f1 = ScSpecFunctionV0 {
            doc: "doc1".try_into().unwrap(),
            name: "my_func".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
        let f2 = ScSpecFunctionV0 {
            doc: "doc2".try_into().unwrap(),
            name: "my_func".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
        let entries = vec![
            ScSpecEntry::FunctionV0(f1),
            ScSpecEntry::FunctionV0(f2),
        ];
        let _spec = ContractSpec::from_entries(&entries);
        panic!("duplicate spec test completed");
    }

    // Otherwise, spawn ourselves as a subprocess with the env var set, and capture stdout/stderr!
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("test_duplicate_warning_stderr")
        .env("RUN_DUPLICATE_SPEC_TEST", "1")
        .output()
        .expect("failed to spawn test subprocess");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let combined = format!("--- STDOUT ---\n{}\n--- STDERR ---\n{}", stdout, stderr);
    assert!(
        combined.contains("WARNING: Duplicate function 'my_func' detected. Keeping the first entry."),
        "Did not find duplicate warning in output:\n{}", combined
    );
}
