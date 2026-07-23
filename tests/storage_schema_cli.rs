//! End-to-end tests for storage-schema analysis through the CLI.
//!
//! Every test here uses the *same* WASM on both sides, so the exported interface
//! is byte-identical and the only thing that can change the verdict is the
//! declared storage layout. That is deliberate: it reproduces the exact
//! condition under which the tool used to report PASSED on a corrupting upgrade.

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

/// Compare `v1.wasm` against itself with the given pair of schemas.
fn run_with_schemas(old_schema: &str, new_schema: &str, extra: &[&str]) -> (i32, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    command
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .arg("--old-storage-schema")
        .arg(schema(old_schema))
        .arg("--new-storage-schema")
        .arg(schema(new_schema))
        .arg("--no-color")
        .args(extra);

    let output = command.output().expect("failed to run binary");
    (
        output.status.code().expect("process terminated by signal"),
        String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
    )
}

/// Without a schema, an identical pair passes and says storage was not checked.
#[test]
fn identical_builds_without_a_schema_pass_but_disclaim_storage() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .arg("--no-color")
        .output()
        .expect("failed to run binary");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Storage layout: NOT analyzed"));
}

/// The headline case: exported interface unchanged, internal struct reordered.
/// This is the upgrade the tool exists to prevent.
#[test]
fn a_reordered_internal_struct_fails_the_run() {
    let (code, stdout, _) = run_with_schemas("lending_v1.toml", "lending_v2_reordered.toml", &[]);

    assert_eq!(
        code, 1,
        "a storage break must fail the run even though the exported interface is identical"
    );
    assert!(
        stdout.contains("STORAGE STRUCT FIELD REORDERED"),
        "the reorder must be reported under a storage-scoped category:\n{stdout}"
    );
    assert!(
        stdout.contains("[declared storage value (persistent)]"),
        "the finding must name the scope and durability it came from:\n{stdout}"
    );
    assert!(
        stdout.contains("PositionState"),
        "the affected type must be named:\n{stdout}"
    );
}

/// A shifted storage-key discriminant orphans every entry written under it.
#[test]
fn a_shifted_storage_key_discriminant_fails_the_run() {
    let (code, stdout, _) = run_with_schemas("lending_v1.toml", "lending_v2_key_shift.toml", &[]);

    assert_eq!(code, 1, "a discriminant shift must fail the run");
    assert!(
        stdout.contains("STORAGE UNION CASE REORDERED"),
        "the discriminant shift must be reported:\n{stdout}"
    );
    assert!(
        stdout.contains("[declared storage key (persistent)]"),
        "the finding must be attributed to the storage key:\n{stdout}"
    );
}

/// An unchanged declared layout is silent and passes.
#[test]
fn an_unchanged_declared_layout_passes() {
    let (code, stdout, _) = run_with_schemas("lending_v1.toml", "lending_v1.toml", &[]);

    assert_eq!(code, 0);
    assert!(stdout.contains("✅ PASSED (No exported-interface or declared-storage breaks)"));
    assert!(!stdout.contains("Storage Struct Field"));
}

/// Appending to a storage value warns but does not block, matching how an
/// appended exported field is treated.
#[test]
fn appending_to_a_storage_value_warns_without_failing() {
    let (code, stdout, _) = run_with_schemas("lending_v1.toml", "lending_v2_appended.toml", &[]);

    assert_eq!(code, 0, "an appended value field is a migration concern");
    assert!(
        stdout.contains("STORAGE STRUCT FIELD ADDED"),
        "the appended field must still be surfaced:\n{stdout}"
    );
}

/// The same append blocks under --strict, so a team can gate on it.
#[test]
fn appending_to_a_storage_value_blocks_under_strict() {
    let (code, _, _) =
        run_with_schemas("lending_v1.toml", "lending_v2_appended.toml", &["--strict"]);
    assert_eq!(code, 1, "strict mode must gate on storage warnings too");
}

/// A manifest that contradicts its own build is rejected outright: acting on a
/// wrong declaration is worse than having none.
#[test]
fn a_manifest_contradicting_the_exported_spec_is_rejected() {
    let (code, _, stderr) = run_with_schemas(
        "contradicts_exported.toml",
        "contradicts_exported.toml",
        &[],
    );

    assert_ne!(code, 0, "a contradictory manifest must not be analyzed");
    assert!(
        stderr.contains("disagrees with that build's exported contract spec"),
        "the rejection must explain itself:\n{stderr}"
    );
    assert!(
        stderr.contains("ConfigData"),
        "the rejection must name the offending type:\n{stderr}"
    );
}

/// Storage findings must appear in JSON with their scope-prefixed categories.
#[test]
fn json_reports_storage_findings_and_fails() {
    let (code, stdout, _) = run_with_schemas(
        "lending_v1.toml",
        "lending_v2_reordered.toml",
        &["--format", "json"],
    );

    assert_eq!(code, 1);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    assert_eq!(json["is_safe"], serde_json::Value::Bool(false));
    assert_eq!(json["scope"]["storage_layout_analyzed"], true);
    assert!(json["counts"]["critical"].as_u64().unwrap() > 0);

    let categories = json["findings_by_category"].as_object().unwrap();
    assert!(
        categories.keys().any(|k| k.starts_with("Storage ")),
        "storage findings must be distinguishable by category: {:?}",
        categories.keys().collect::<Vec<_>>()
    );
}

/// `--explain` must offer storage-specific guidance, framed around stored data
/// rather than broken callers.
#[test]
fn explain_gives_storage_specific_guidance() {
    let (_, stdout, _) = run_with_schemas(
        "lending_v1.toml",
        "lending_v2_reordered.toml",
        &["--explain"],
    );

    assert!(
        stdout.contains("corrupts stored data"),
        "storage guidance must speak to data corruption:\n{stdout}"
    );
}

/// Supplying only one side is refused: a layout change is only visible as a
/// difference between two snapshots.
#[test]
fn one_sided_schema_input_is_refused() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .arg("--new-storage-schema")
        .arg(schema("lending_v1.toml"))
        .output()
        .expect("failed to run binary");

    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("--old-storage-schema"),
        "the error must name the missing side:\n{stderr}"
    );
}

/// A schema cannot be applied across a batch of different contracts.
#[test]
fn batch_mode_refuses_storage_schema_flags() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/wasm");
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--old-dir")
        .arg(&dir)
        .arg("--new-dir")
        .arg(&dir)
        .arg("--old-storage-schema")
        .arg(schema("lending_v1.toml"))
        .arg("--new-storage-schema")
        .arg(schema("lending_v1.toml"))
        .output()
        .expect("failed to run binary");

    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("cannot be used with batch mode"),
        "the refusal must explain why:\n{stderr}"
    );
}
