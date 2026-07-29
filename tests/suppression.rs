//! Integration tests for the suppression config (`.safeguard.toml`).
//!
//! These drive the compiled binary with `--config` against the checked-in
//! `v1 -> v2` fixtures, which produce three Critical findings:
//!
//! - `Event Enum Case Value Changed` on `StatusEvent.Paused`
//! - `Function Signature Changed`     on `initialize`
//! - `Struct Field Removed`           on `ConfigData.threshold`
//!
//! and assert that suppressions flip the failing set without hiding findings.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Write `contents` to a uniquely named TOML file in the per-test temp dir and
/// return its path. `CARGO_TARGET_TMPDIR` is provided to integration tests.
fn write_config(name: &str, contents: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}.safeguard.toml"));
    std::fs::write(&path, contents).expect("failed to write temp config");
    path
}

fn all_critical_suppressions() -> &'static str {
    r#"
    [[suppress]]
    category = "Event Enum Case Value Changed"
    target   = "StatusEvent.Paused"
    reason   = "Reviewed: indexers already updated."

    [[suppress]]
    category = "Function Signature Changed"
    target   = "initialize"
    reason   = "Planned re-init for the v2 migration."

    [[suppress]]
    category = "Struct Field Removed"
    target   = "ConfigData.threshold"
    "#
}

fn temp_dir(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "{}-{}",
        name,
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("failed to create temp dir");
    path
}

/// Run the binary in JSON mode comparing `v1 -> v2`, optionally with a config.
/// Returns (parsed JSON, exit code).
fn run(config: Option<&PathBuf>) -> (Value, i32) {
    run_ext(config, &[], None)
}

fn run_ext(config: Option<&PathBuf>, extra_args: &[&str], cwd: Option<&PathBuf>) -> (Value, i32) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    cmd.arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json"]);
    if let Some(path) = config {
        cmd.args(["--config".as_ref(), path.as_os_str()]);
    }
    cmd.args(extra_args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    let output = cmd.output().expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}"));
    let code = output.status.code().expect("process terminated by signal");
    (json, code)
}

/// Collect every finding across all categories as (category, target, suppressed).
fn findings(json: &Value) -> Vec<(String, Option<String>, bool)> {
    json["findings_by_category"]
        .as_object()
        .expect("findings_by_category must be an object")
        .values()
        .flat_map(|arr| arr.as_array().expect("findings must be an array"))
        .map(|f| {
            (
                f["category"].as_str().unwrap().to_string(),
                f["target"].as_str().map(str::to_string),
                f["suppressed"].as_bool().unwrap_or(false),
            )
        })
        .collect()
}

#[test]
fn rule_id_based_suppression_matches_stable_identifier() {
    let config = write_config(
        "rule-id",
        r#"
        [[suppress]]
        rule_id = "struct_field_removed"
        target  = "ConfigData.threshold"
        reason  = "Reviewed storage migration"
        "#,
    );

    let (json, code) = run(Some(&config));

    assert_eq!(code, 0, "suppressing by rule_id should pass the run");
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 1);
    assert!(
        findings(&json)
            .iter()
            .any(|(c, t, s)| c == "Struct Field Removed"
                && t.as_deref() == Some("ConfigData.threshold")
                && *s),
        "the removed field must appear as suppressed when matched by rule_id"
    );
}

#[test]
fn suppressing_all_criticals_passes_but_still_lists_them() {
    let config = write_config("all", all_critical_suppressions());

    let (json, code) = run(Some(&config));

    // A suppressed Critical no longer fails the run...
    assert_eq!(code, 0, "all criticals suppressed -> must exit 0");
    assert_eq!(json["is_safe"], Value::Bool(true));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 3);

    // ...but the criticals are still counted and still listed, just marked.
    assert_eq!(json["counts"]["critical"].as_u64().unwrap(), 3);
    let all = findings(&json);
    let suppressed: Vec<_> = all.iter().filter(|(_, _, s)| *s).collect();
    assert_eq!(
        suppressed.len(),
        3,
        "all three criticals must be listed as suppressed"
    );
    assert!(
        all.iter().any(|(c, t, s)| c == "Struct Field Removed"
            && t.as_deref() == Some("ConfigData.threshold")
            && *s),
        "the removed field must appear, flagged suppressed"
    );
}

#[test]
fn default_config_is_auto_loaded_without_no_config() {
    let cwd = temp_dir("auto-load-default-config");
    std::fs::write(cwd.join(".safeguard.toml"), all_critical_suppressions())
        .expect("failed to write default config");

    let (json, code) = run_ext(None, &[], Some(&cwd));

    assert_eq!(code, 0, "default .safeguard.toml should still load");
    assert_eq!(json["is_safe"], Value::Bool(true));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 3);
}

#[test]
fn no_config_ignores_auto_loaded_default_config() {
    let cwd = temp_dir("no-config-ignores-default");
    std::fs::write(cwd.join(".safeguard.toml"), all_critical_suppressions())
        .expect("failed to write default config");

    let (json, code) = run_ext(None, &["--no-config"], Some(&cwd));

    assert_eq!(code, 1, "--no-config should expose unsuppressed criticals");
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 0);
    assert_eq!(json["counts"]["critical"].as_u64().unwrap(), 3);
}

#[test]
fn no_config_conflicts_with_explicit_config() {
    let config = write_config("conflict", all_critical_suppressions());
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json"])
        .args(["--config".as_ref(), config.as_os_str()])
        .arg("--no-config")
        .output()
        .expect("failed to run binary");

    assert!(
        !output.status.success(),
        "--no-config and --config should be rejected together"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--config") && stderr.contains("--no-config"),
        "conflict error should mention both flags: {stderr}"
    );
}

#[test]
fn non_matching_suppression_leaves_run_failing() {
    // Right category, wrong target -> exact match means it must NOT apply.
    let config = write_config(
        "wrong-target",
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.some_other_field"
        "#,
    );

    let (json, code) = run(Some(&config));

    assert_eq!(code, 1, "a non-matching rule must not rescue the run");
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 0);
    assert!(findings(&json).iter().all(|(_, _, s)| !s));
}

#[test]
fn partial_suppression_still_fails_on_remaining_critical() {
    // Suppress two of the three criticals; the third must still fail the run.
    let config = write_config(
        "partial",
        r#"
        [[suppress]]
        category = "Event Enum Case Value Changed"
        target   = "StatusEvent.Paused"

        [[suppress]]
        category = "Function Signature Changed"
        target   = "initialize"
        "#,
    );

    let (json, code) = run(Some(&config));

    assert_eq!(code, 1, "one unsuppressed critical must still fail");
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 2);
}

#[test]
fn no_config_behaves_exactly_as_today() {
    // No --config and (by virtue of the temp cwd) no default file -> the run
    // fails on the criticals with nothing suppressed, exactly as before.
    let (json, code) = run(None);

    assert_eq!(code, 1);
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 0);
    assert_eq!(json["counts"]["critical"].as_u64().unwrap(), 3);
}

#[test]
fn missing_explicit_config_is_an_error() {
    // An explicitly named config that does not exist must be a hard error,
    // so typos are never silently treated as "no suppressions".
    let missing = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("does-not-exist.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--config".as_ref(), missing.as_os_str()])
        .output()
        .expect("failed to run binary");

    assert!(
        !output.status.success(),
        "missing explicit config must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("suppression config"),
        "error should mention the suppression config: {stderr}"
    );
}
