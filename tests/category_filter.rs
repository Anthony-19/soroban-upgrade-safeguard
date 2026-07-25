use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn include_category_filters_out_other_categories() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--include-category", "Environment"])
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    // Only Environment findings should remain, so no critical findings
    assert_eq!(code, 0, "Only Environment findings should not be critical");

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("output must be valid JSON");
    assert_eq!(json["counts"]["critical"], 0);
    assert!(json["filtered_count"].as_u64().unwrap_or(0) > 0);
}

#[test]
fn exclude_category_removes_specified_findings() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--exclude-category", "Struct Field Removed"])
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    // Struct Field Removed is excluded, but other critical findings remain
    assert_eq!(code, 1, "Other critical findings should still fail");

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("output must be valid JSON");
    assert!(json["filtered_count"].as_u64().unwrap_or(0) > 0);
}

#[test]
fn exclude_multiple_categories() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args([
            "--exclude-category",
            "Struct Field Removed",
            "--exclude-category",
            "Function Signature Changed",
        ])
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("output must be valid JSON");
    assert!(json["filtered_count"].as_u64().unwrap_or(0) > 0);
}

#[test]
fn invalid_category_name_fails_with_clear_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .args(["--include-category", "NonExistentCategory"])
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");

    assert!(!output.status.success());
    assert!(
        stderr.contains("Unknown category"),
        "Should mention unknown category. stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("NonExistentCategory"),
        "Should mention the invalid name. stderr: {}",
        stderr
    );
}

#[test]
fn include_and_exclude_together() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--include-category", "Struct Field Removed"])
        .args(["--exclude-category", "Struct Field Removed"])
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    // Include + exclude same category = exclude wins, no findings displayed
    assert_eq!(code, 0);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("output must be valid JSON");
    // Exclude wins over include, so all findings are filtered out
    // total_findings is the original count; filtered_count reflects what was hidden
    let filtered = json["filtered_count"].as_u64().unwrap_or(0);
    assert!(
        filtered > 0,
        "All findings should be filtered: {}",
        filtered
    );
    assert_eq!(
        json["findings_by_category"]
            .as_object()
            .map(|o| o.len())
            .unwrap_or(0),
        0
    );
    assert_eq!(json["counts"]["critical"], 0);
    assert_eq!(json["counts"]["warning"], 0);
    assert_eq!(json["counts"]["info"], 0);
}

#[test]
fn text_output_shows_filtered_count() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--exclude-category", "Struct Field Removed"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");

    assert!(stdout.contains("Filtered"), "Should mention filtered count");
    assert!(
        stdout.contains("--include-category/--exclude-category"),
        "Should explain why findings were filtered"
    );
}
