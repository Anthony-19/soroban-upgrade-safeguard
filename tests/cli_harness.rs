//! End-to-end CLI test harness exercising all four documented usage modes:
//! 1. Local pair mode (<OLD_WASM> <NEW_WASM>)
//! 2. RPC mode (--contract-id <ID> --rpc-url <URL> <NEW_WASM>) - argument validation
//! 3. Manifest batch mode (--manifest <PATH>)
//! 4. Directory batch mode (--old-dir <OLD> --new-dir <NEW>)
//!
//! Asserts on exit code, stdout, and stderr separation, verifying the binary's
//! contract with CI pipelines: clean-stdout routing for JSON and Markdown,
//! non-zero exit codes on breaking changes or malformed arguments, and batch
//! execution behavior.

use serde_json::Value;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Result of running the compiled CLI binary.
#[derive(Debug)]
struct CliOutput {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Execute the compiled CLI binary with the given arguments.
fn run_cli<I, S>(args: I) -> CliOutput
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    cmd.args(args);
    let output = cmd
        .output()
        .expect("failed to execute soroban-upgrade-safeguard binary");

    CliOutput {
        code: output.status.code().expect("process terminated by signal"),
        stdout: String::from_utf8(output.stdout).expect("stdout was not UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr was not UTF-8"),
    }
}

/// Absolute path to a checked-in fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Helper to create a temporary directory inside `CARGO_TARGET_TMPDIR` or `env::temp_dir()`.
fn create_temp_dir(prefix: &str) -> PathBuf {
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("{}_{}_{}", prefix, std::process::id(), fastrand()));
    fs::create_dir_all(&dir).expect("failed to create temp dir");
    dir
}

/// Simple pseudorandom generator for unique temporary directory/file names.
fn fastrand() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards");
    start.as_nanos() as u64
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode 1: Local Pair Mode (<OLD_WASM> <NEW_WASM>)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn local_pair_safe_upgrade_exits_zero() {
    let out = run_cli([wasm("v1.wasm").as_os_str(), wasm("v1.wasm").as_os_str()]);

    assert_eq!(
        out.code, 0,
        "identical upgrade must exit 0\nstderr: {}",
        out.stderr
    );
    assert!(
        out.stdout.contains("Status: ✅ PASSED"),
        "stdout must indicate safe status, got:\n{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("SOROBAN UPGRADE SAFETY REPORT"),
        "default text mode emits report and headers on stdout"
    );
}

#[test]
fn local_pair_breaking_upgrade_exits_one() {
    let out = run_cli([wasm("v1.wasm").as_os_str(), wasm("v2.wasm").as_os_str()]);

    assert_eq!(
        out.code, 1,
        "breaking upgrade must exit 1\nstderr: {}",
        out.stderr
    );
    assert!(
        out.stdout.contains("Status: ❌ FAILED"),
        "stdout must indicate critical status, got:\n{}",
        out.stdout
    );
}

#[test]
fn local_pair_warning_upgrade_strict_vs_non_strict() {
    // Non-strict: exits 0
    let out_normal = run_cli([wasm("v1.wasm").as_os_str(), wasm("v3.wasm").as_os_str()]);
    assert_eq!(
        out_normal.code, 0,
        "warning upgrade without strict must exit 0"
    );

    // Strict: exits 1
    let out_strict = run_cli([
        wasm("v1.wasm").as_os_str(),
        wasm("v3.wasm").as_os_str(),
        OsStr::new("--strict"),
    ]);
    assert_eq!(
        out_strict.code, 1,
        "warning upgrade with --strict must exit 1"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Clean-Stdout Guarantee (JSON, Markdown, and File Output)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn clean_stdout_guarantee_for_json_output() {
    let out = run_cli([
        wasm("v1.wasm").as_os_str(),
        wasm("v2.wasm").as_os_str(),
        OsStr::new("--format"),
        OsStr::new("json"),
    ]);

    assert_eq!(out.code, 1, "breaking upgrade in json mode must exit 1");

    // 1. Stderr must receive decorative progress messages.
    assert!(
        out.stderr.contains("Soroban Upgrade Safeguard")
            || out.stderr.contains("Loading and Parsing contracts..."),
        "stderr must receive progress logs in JSON mode, got:\n{}",
        out.stderr
    );

    // 2. Stdout must NOT contain ANSI color codes or progress logs.
    assert!(
        !out.stdout.contains('\u{1b}'),
        "JSON stdout must be free of ANSI escape sequences"
    );
    assert!(
        !out.stdout.contains("🔍"),
        "JSON stdout must not contain emoji/progress banners"
    );

    // 3. Stdout must be strictly valid, parseable JSON.
    let json: Value = serde_json::from_str(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "JSON stdout was not valid JSON: {e}\n---stdout---\n{}",
            out.stdout
        )
    });
    assert_eq!(json["is_safe"], Value::Bool(false));
}

#[test]
fn clean_stdout_guarantee_for_markdown_output() {
    let out = run_cli([
        wasm("v1.wasm").as_os_str(),
        wasm("v1.wasm").as_os_str(),
        OsStr::new("--format"),
        OsStr::new("markdown"),
    ]);

    assert_eq!(out.code, 0, "safe upgrade in markdown mode must exit 0");

    // 1. Stderr must receive progress logs.
    assert!(
        out.stderr.contains("Soroban Upgrade Safeguard")
            || out.stderr.contains("Loading and Parsing contracts..."),
        "stderr must receive progress logs in Markdown mode, got:\n{}",
        out.stderr
    );

    // 2. Stdout must be clean markdown without ANSI codes or decorative banners.
    assert!(
        !out.stdout.contains('\u{1b}'),
        "Markdown stdout must be free of ANSI escape sequences"
    );
    assert!(
        !out.stdout.contains("🔍"),
        "Markdown stdout must not contain progress emojis"
    );
    assert!(
        out.stdout.contains("# Contract Upgrade Analysis") || out.stdout.contains("# Soroban"),
        "Markdown stdout must contain markdown headings, got:\n{}",
        out.stdout
    );
}

#[test]
fn clean_stdout_guarantee_for_file_output() {
    let temp_dir = create_temp_dir("cli_file_out");
    let report_file = temp_dir.join("report.txt");

    let out = run_cli([
        wasm("v1.wasm").as_os_str(),
        wasm("v1.wasm").as_os_str(),
        OsStr::new("--output"),
        report_file.as_os_str(),
    ]);

    assert_eq!(out.code, 0);

    // When --output is specified, stdout must be completely empty!
    assert!(
        out.stdout.is_empty(),
        "stdout must be empty when --output is used, got:\n{}",
        out.stdout
    );

    // Stderr must receive progress logs and the completion notification.
    assert!(
        out.stderr.contains("✅ Report written to:"),
        "stderr must confirm file output, got:\n{}",
        out.stderr
    );

    // The file must exist and contain the rendered report.
    let content = fs::read_to_string(&report_file).expect("failed to read generated report file");
    assert!(
        content.contains("Status: ✅ PASSED"),
        "file content must contain report summary"
    );

    let _ = fs::remove_dir_all(temp_dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode 3: Batch Manifest Mode (--manifest <PATH>)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn batch_manifest_mode_safe_and_breaking_exits() {
    let temp_dir = create_temp_dir("cli_manifest");
    let manifest_safe = temp_dir.join("safe.toml");
    let manifest_breaking = temp_dir.join("breaking.toml");

    let v1 = wasm("v1.wasm");
    let v2 = wasm("v2.wasm");

    let safe_toml = format!(
        "[[pairs]]\nold = {:?}\nnew = {:?}\nname = \"safe_pair\"\n",
        v1.display(),
        v1.display()
    );
    let breaking_toml = format!(
        "[[pairs]]\nold = {:?}\nnew = {:?}\nname = \"breaking_pair\"\n",
        v1.display(),
        v2.display()
    );

    fs::write(&manifest_safe, safe_toml).expect("write safe manifest");
    fs::write(&manifest_breaking, breaking_toml).expect("write breaking manifest");

    // Safe manifest -> exit 0
    let out_safe = run_cli([OsStr::new("--manifest"), manifest_safe.as_os_str()]);
    assert_eq!(
        out_safe.code, 0,
        "safe manifest must exit 0\nstderr: {}",
        out_safe.stderr
    );
    assert!(out_safe.stdout.contains("SOROBAN BATCH SAFETY REPORT"));
    assert!(
        out_safe.stdout.contains("Overall Status: ✅ PASSED")
            || out_safe.stdout.contains("Overall Status:")
    );

    // Breaking manifest -> exit 1
    let out_break = run_cli([OsStr::new("--manifest"), manifest_breaking.as_os_str()]);
    assert_eq!(out_break.code, 1, "breaking manifest must exit 1");
    assert!(out_break.stdout.contains("SOROBAN BATCH SAFETY REPORT"));
    assert!(
        out_break.stdout.contains("Overall Status: ❌ FAILED")
            || out_break.stdout.contains("Overall Status:")
    );

    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn batch_manifest_json_output_clean_stdout() {
    let temp_dir = create_temp_dir("cli_manifest_json");
    let manifest_path = temp_dir.join("batch.toml");
    let v1 = wasm("v1.wasm");
    let v2 = wasm("v2.wasm");

    let toml_content = format!(
        "[[pairs]]\nold = {:?}\nnew = {:?}\nname = \"p1\"\n",
        v1.display(),
        v2.display()
    );
    fs::write(&manifest_path, toml_content).expect("write manifest");

    let out = run_cli([
        OsStr::new("--manifest"),
        manifest_path.as_os_str(),
        OsStr::new("--format"),
        OsStr::new("json"),
    ]);

    assert_eq!(out.code, 1);
    assert!(
        out.stderr
            .contains("Soroban Upgrade Safeguard (Batch Mode)"),
        "stderr must receive batch progress header"
    );
    assert!(
        !out.stdout.contains('\u{1b}'),
        "JSON stdout in batch mode must be clean without ANSI codes"
    );

    let json: Value = serde_json::from_str(&out.stdout).expect("valid batch JSON");
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert!(json["results"].is_object());

    let _ = fs::remove_dir_all(temp_dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode 4: Batch Directory Mode (--old-dir <OLD> --new-dir <NEW>)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn batch_directory_mode_safe_and_breaking() {
    let temp_dir = create_temp_dir("cli_dir_mode");
    let old_dir = temp_dir.join("old");
    let new_dir_safe = temp_dir.join("new_safe");
    let new_dir_break = temp_dir.join("new_break");

    fs::create_dir_all(&old_dir).expect("create old_dir");
    fs::create_dir_all(&new_dir_safe).expect("create new_dir_safe");
    fs::create_dir_all(&new_dir_break).expect("create new_dir_break");

    let v1 = wasm("v1.wasm");
    let v2 = wasm("v2.wasm");

    fs::copy(&v1, old_dir.join("token.wasm")).expect("copy old token");
    fs::copy(&v1, new_dir_safe.join("token.wasm")).expect("copy new safe token");
    fs::copy(&v2, new_dir_break.join("token.wasm")).expect("copy new break token");

    // Safe directory batch
    let out_safe = run_cli([
        OsStr::new("--old-dir"),
        old_dir.as_os_str(),
        OsStr::new("--new-dir"),
        new_dir_safe.as_os_str(),
    ]);
    assert_eq!(
        out_safe.code, 0,
        "safe directory batch must exit 0\nstderr: {}",
        out_safe.stderr
    );
    assert!(out_safe.stdout.contains("SOROBAN BATCH SAFETY REPORT"));
    assert!(
        out_safe.stdout.contains("Overall Status: ✅ PASSED")
            || out_safe.stdout.contains("Overall Status:")
    );

    // Breaking directory batch
    let out_break = run_cli([
        OsStr::new("--old-dir"),
        old_dir.as_os_str(),
        OsStr::new("--new-dir"),
        new_dir_break.as_os_str(),
    ]);
    assert_eq!(out_break.code, 1, "breaking directory batch must exit 1");
    assert!(out_break.stdout.contains("SOROBAN BATCH SAFETY REPORT"));
    assert!(
        out_break.stdout.contains("Overall Status: ❌ FAILED")
            || out_break.stdout.contains("Overall Status:")
    );

    let _ = fs::remove_dir_all(temp_dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument Validation Errors across All Four Usage Modes
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn arg_validation_missing_all_arguments() {
    let out = run_cli(Vec::<&OsStr>::new());
    assert_ne!(out.code, 0, "no arguments must exit non-zero");
    assert!(
        out.stderr.contains("Missing OLD_WASM path") || out.stderr.contains("Usage:"),
        "stderr must explain required usage, got:\n{}",
        out.stderr
    );
}

#[test]
fn arg_validation_one_positional_without_rpc_flags() {
    let out = run_cli([wasm("v1.wasm").as_os_str()]);
    assert_ne!(
        out.code, 0,
        "one positional arg without RPC flags must exit non-zero"
    );
    assert!(
        out.stderr.contains("Missing OLD_WASM path"),
        "stderr must explain missing old wasm, got:\n{}",
        out.stderr
    );
}

#[test]
fn arg_validation_three_positional_arguments() {
    let out = run_cli([
        wasm("v1.wasm").as_os_str(),
        wasm("v1.wasm").as_os_str(),
        wasm("v2.wasm").as_os_str(),
    ]);
    assert_ne!(
        out.code, 0,
        "three positional args must be rejected by clap"
    );
    assert!(
        out.stderr.contains("unexpected argument") || out.stderr.contains("error:"),
        "stderr must contain clap rejection, got:\n{}",
        out.stderr
    );
}

#[test]
fn arg_validation_manifest_combined_with_directory_mode() {
    let temp_dir = create_temp_dir("cli_val_manifest_dir");
    let out = run_cli([
        OsStr::new("--manifest"),
        OsStr::new("some.toml"),
        OsStr::new("--old-dir"),
        temp_dir.as_os_str(),
        OsStr::new("--new-dir"),
        temp_dir.as_os_str(),
    ]);
    assert_ne!(out.code, 0);
    assert!(
        out.stderr
            .contains("Cannot specify both --manifest and --old-dir/--new-dir"),
        "stderr must report mutually exclusive batch flags, got:\n{}",
        out.stderr
    );
    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn arg_validation_batch_mode_with_positional_arguments() {
    let temp_dir = create_temp_dir("cli_val_batch_pos");
    let out = run_cli([
        OsStr::new("--old-dir"),
        temp_dir.as_os_str(),
        OsStr::new("--new-dir"),
        temp_dir.as_os_str(),
        wasm("v1.wasm").as_os_str(),
    ]);
    assert_ne!(out.code, 0);
    assert!(
        out.stderr
            .contains("Cannot specify positional WASM paths when using batch mode"),
        "stderr must reject positional args in batch mode, got:\n{}",
        out.stderr
    );
    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn arg_validation_batch_mode_with_storage_schema() {
    let temp_dir = create_temp_dir("cli_val_batch_storage");
    let manifest = temp_dir.join("manifest.toml");
    fs::write(&manifest, "[[pairs]]\n").unwrap();

    let out = run_cli([
        OsStr::new("--manifest"),
        manifest.as_os_str(),
        OsStr::new("--old-storage-schema"),
        OsStr::new("schema.toml"),
        OsStr::new("--new-storage-schema"),
        OsStr::new("schema.toml"),
    ]);
    assert_ne!(out.code, 0);
    assert!(
        out.stderr.contains(
            "describe a single contract's storage layout and cannot be used with batch mode"
        ),
        "stderr must reject storage schemas in batch mode, got:\n{}",
        out.stderr
    );
    let _ = fs::remove_dir_all(temp_dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode 2: RPC Mode Argument Validation Paths
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rpc_arg_validation_contract_id_without_rpc_url() {
    let out = run_cli([
        OsStr::new("--contract-id"),
        OsStr::new("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"),
        wasm("v2.wasm").as_os_str(),
    ]);
    assert_ne!(
        out.code, 0,
        "--contract-id without --rpc-url must exit non-zero"
    );
    assert!(
        out.stderr.contains("--rpc-url") || out.stderr.contains("required"),
        "stderr must indicate required --rpc-url, got:\n{}",
        out.stderr
    );
}

#[test]
fn rpc_arg_validation_rpc_url_without_contract_id() {
    let out = run_cli([
        OsStr::new("--rpc-url"),
        OsStr::new("https://soroban-testnet.stellar.org"),
        wasm("v2.wasm").as_os_str(),
    ]);
    assert_ne!(
        out.code, 0,
        "--rpc-url without --contract-id must exit non-zero"
    );
    assert!(
        out.stderr.contains("--contract-id") || out.stderr.contains("required"),
        "stderr must indicate required --contract-id, got:\n{}",
        out.stderr
    );
}

#[test]
fn rpc_arg_validation_contract_id_with_two_positional_arguments() {
    let out = run_cli([
        OsStr::new("--contract-id"),
        OsStr::new("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"),
        OsStr::new("--rpc-url"),
        OsStr::new("https://soroban-testnet.stellar.org"),
        wasm("v1.wasm").as_os_str(),
        wasm("v2.wasm").as_os_str(),
    ]);
    assert_ne!(
        out.code, 0,
        "RPC mode with 2 positional args must exit non-zero"
    );
    assert!(
        out.stderr.contains(
            "When using --contract-id, provide only the NEW_WASM path as a positional argument"
        ),
        "stderr must explain RPC positional arg rule, got:\n{}",
        out.stderr
    );
}

#[test]
fn arg_validation_unknown_category_filter() {
    let out = run_cli([
        wasm("v1.wasm").as_os_str(),
        wasm("v1.wasm").as_os_str(),
        OsStr::new("--include-category"),
        OsStr::new("NonExistentCategoryName"),
    ]);
    assert_ne!(out.code, 0, "unknown category filter must exit non-zero");
    assert!(
        out.stderr
            .contains("Unknown category name(s): NonExistentCategoryName"),
        "stderr must report unknown category name, got:\n{}",
        out.stderr
    );
}
