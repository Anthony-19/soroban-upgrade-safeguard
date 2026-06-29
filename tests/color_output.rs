use std::path::PathBuf;
use std::process::Command;

use soroban_upgrade_safeguard::color::should_disable_color;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn color_decision_respects_no_color_flag_when_stdout_is_tty() {
    assert!(should_disable_color(true, false, true));
}

#[test]
fn color_decision_respects_no_color_env_when_stdout_is_tty() {
    assert!(should_disable_color(false, true, true));
}

#[test]
fn color_decision_disables_color_for_non_tty_stdout() {
    assert!(should_disable_color(false, false, false));
}

#[test]
fn color_decision_allows_color_when_no_disable_signal_exists() {
    assert!(!should_disable_color(false, false, true));
}

#[test]
fn color_disabled_by_no_color_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--no-color")
        .env("CLICOLOR_FORCE", "1") // Try to force colors
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    assert!(
        !stdout.contains('\u{1b}'),
        "Output must not contain ANSI escape codes when --no-color is set. Output:\n{}",
        stdout
    );
}

#[test]
fn color_disabled_by_no_color_env() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .env("NO_COLOR", "1")
        .env("CLICOLOR_FORCE", "1") // Try to force colors
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    assert!(
        !stdout.contains('\u{1b}'),
        "Output must not contain ANSI escape codes when NO_COLOR env var is set. Output:\n{}",
        stdout
    );
}

#[test]
fn color_disabled_by_non_tty() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .env("CLICOLOR_FORCE", "1")
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");

    // In our implementation:
    // `if args.no_color || std::env::var_os("NO_COLOR").is_some() || !std::io::IsTerminal::is_terminal(&std::io::stdout())`
    // Since stdout is a pipe here (not a terminal), color is disabled.
    assert!(
        !stdout.contains('\u{1b}'),
        "Output must not contain ANSI escape codes when not a TTY, even if CLICOLOR_FORCE is set. Output:\n{}",
        stdout
    );
}
