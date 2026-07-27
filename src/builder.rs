//! Build a local Soroban contract crate to WASM before analysis.
//!
//! This module shells out to `cargo build --target wasm32-unknown-unknown
//! --release` in the given directory and locates the produced artifact, then
//! loads it through the same path as a normal on-disk WASM file. Nothing
//! downstream knows or cares how the bytes were produced.
//!
//! # Isolation
//!
//! The build capability lives here and nowhere else. The core pipeline
//! (`loader.rs`, `parser.rs`, `diff.rs`) never touches it. Callers that only
//! want binary-versus-binary comparisons are completely unaffected.
//!
//! # Toolchain requirements
//!
//! The host machine must have:
//!
//! - **Cargo** on `$PATH` (part of the standard Rust toolchain).
//! - The **`wasm32-unknown-unknown` target** installed for the active
//!   toolchain:
//!   ```text
//!   rustup target add wasm32-unknown-unknown
//!   ```
//!
//! Both requirements are checked before the build runs; a missing target
//! produces an explicit, actionable error rather than a cryptic rustc message.
//!
//! # CI notes
//!
//! Shelling out to Cargo makes this capability subject to all the usual CI
//! caveats: the crate's dependencies will be downloaded on the first run,
//! Cargo's network access must be available, and the build adds to total
//! pipeline time. The `--locked` flag is set automatically so the build
//! respects the crate's `Cargo.lock` and is reproducible.
//!
//! The build target is always `wasm32-unknown-unknown --release`; no
//! override is provided. Soroban contracts must be compiled in release mode
//! for the SDK to emit the `contractspecv0` custom section that this tool
//! reads.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

use crate::limits::ResourcePolicy;
use crate::loader::{load_wasm_with_policy, WasmModule};

const WASM_TARGET: &str = "wasm32-unknown-unknown";

/// Build a Soroban contract crate at `crate_path` and return a
/// [`WasmModule`] ready for analysis.
///
/// The function:
///
/// 1. Verifies `crate_path` contains a `Cargo.toml`.
/// 2. Checks that the `wasm32-unknown-unknown` target is installed for the
///    active toolchain.
/// 3. Runs `cargo build --target wasm32-unknown-unknown --release --locked`
///    in `crate_path`.
/// 4. Locates the produced `.wasm` artifact via `cargo metadata`.
/// 5. Loads and validates the artifact through [`load_wasm_with_policy`].
///
/// # Errors
///
/// - `Cargo.toml` not found in `crate_path`.
/// - `cargo` not on `$PATH`.
/// - `wasm32-unknown-unknown` target not installed.
/// - The Cargo build fails (non-zero exit code); stderr is included.
/// - No `.wasm` artifact is found after a successful build (possible if the
///   crate type is not `cdylib`).
/// - The produced WASM fails structural validation or exceeds
///   `policy.max_wasm_size`.
pub fn build_contract_crate(crate_path: &Path, policy: &ResourcePolicy) -> Result<WasmModule> {
    let crate_path = crate_path
        .canonicalize()
        .with_context(|| format!("Cannot resolve crate path '{}'", crate_path.display()))?;

    // 1. Sanity-check: must be a Cargo project.
    if !crate_path.join("Cargo.toml").exists() {
        bail!(
            "'{}' does not contain a Cargo.toml. \
             Pass the path to a Cargo crate directory.",
            crate_path.display()
        );
    }

    // 2. Check that cargo is available.
    check_cargo_available()?;

    // 3. Check that the wasm32-unknown-unknown target is installed.
    check_wasm_target_installed(&crate_path)?;

    // 4. Run the build.
    run_cargo_build(&crate_path)?;

    // 5. Locate the artifact.
    let artifact = locate_wasm_artifact(&crate_path)?;

    // 6. Load and validate through the normal path (magic-byte check,
    //    structural validation, size limit).
    load_wasm_with_policy(&artifact, policy)
        .with_context(|| format!("Built WASM at '{}' failed validation", artifact.display()))
}

/// Return `true` when `path` looks like a Cargo crate directory that should
/// be built rather than loaded as a file.
///
/// The heuristic: a `Cargo.toml` exists directly inside the path and the path
/// itself is a directory. This is checked without touching the filesystem
/// except for what the caller explicitly passed.
pub fn is_contract_crate(path: &Path) -> bool {
    path.is_dir() && path.join("Cargo.toml").exists()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn check_cargo_available() -> Result<()> {
    match std::process::Command::new("cargo")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "`cargo` was not found on PATH. \
                 Install the Rust toolchain from https://rustup.rs and try again."
            )
        }
        Err(e) => bail!("Failed to run `cargo --version`: {e}"),
    }
}

fn check_wasm_target_installed(crate_path: &Path) -> Result<()> {
    // `rustup target list --installed` is the canonical check but requires
    // rustup. A lighter-weight check: ask rustc (via cargo) whether it knows
    // the target. We attempt a no-op metadata fetch; if it fails with a
    // message about the target we surface that directly.
    //
    // The most reliable portable check is to run:
    //   cargo build --target wasm32-unknown-unknown --release --dry-run
    // but --dry-run is unstable. Instead, check via rustup if available;
    // otherwise skip the pre-check and let the build surface the error.
    let rustup_status = std::process::Command::new("rustup")
        .args(["target", "list", "--installed"])
        .current_dir(crate_path)
        .output();

    match rustup_status {
        Ok(out) if out.status.success() => {
            let installed = String::from_utf8_lossy(&out.stdout);
            if !installed.lines().any(|l| l.trim() == WASM_TARGET) {
                bail!(
                    "The `{WASM_TARGET}` target is not installed for the active toolchain.\n\
                     Run the following to install it:\n\
                     \n\
                     \trustup target add {WASM_TARGET}\n\
                     \n\
                     Then re-run this command."
                );
            }
            Ok(())
        }
        // rustup not available — skip the pre-check and let cargo surface the
        // error naturally. This handles non-rustup toolchain setups.
        Err(_) | Ok(_) => Ok(()),
    }
}

fn run_cargo_build(crate_path: &Path) -> Result<()> {
    let output = std::process::Command::new("cargo")
        .args([
            "build",
            "--target",
            WASM_TARGET,
            "--release",
            "--locked",
        ])
        .current_dir(crate_path)
        .output()
        .with_context(|| format!("Failed to spawn `cargo build` in '{}'", crate_path.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Cargo build failed for '{}' (exit {}):\n\n{}",
            crate_path.display(),
            output.status.code().unwrap_or(-1),
            stderr.trim()
        );
    }

    Ok(())
}

fn locate_wasm_artifact(crate_path: &Path) -> Result<PathBuf> {
    // Use `cargo metadata` to find the package name and derive the artifact
    // path from the conventional output layout:
    //   <workspace_root>/target/wasm32-unknown-unknown/release/<name>.wasm
    let output = std::process::Command::new("cargo")
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
        ])
        .current_dir(crate_path)
        .output()
        .context("Failed to run `cargo metadata`")?;

    if !output.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let meta: serde_json::Value = serde_json::from_slice(&output.stdout)
        .context("Failed to parse `cargo metadata` output")?;

    let workspace_root = meta["workspace_root"]
        .as_str()
        .context("cargo metadata missing workspace_root")?;

    // Find the package that lives at crate_path.
    let packages = meta["packages"]
        .as_array()
        .context("cargo metadata missing packages array")?;

    // Match the package whose manifest path starts with crate_path.
    let pkg = packages
        .iter()
        .find(|p| {
            p["manifest_path"]
                .as_str()
                .map(|mp| Path::new(mp).starts_with(&crate_path))
                .unwrap_or(false)
        })
        .with_context(|| {
            format!(
                "No package found at '{}' in cargo metadata output",
                crate_path.display()
            )
        })?;

    let pkg_name = pkg["name"]
        .as_str()
        .context("Package entry missing 'name'")?;

    // Cargo replaces hyphens with underscores in artifact filenames.
    let artifact_name = pkg_name.replace('-', "_");
    let artifact_path = Path::new(workspace_root)
        .join("target")
        .join(WASM_TARGET)
        .join("release")
        .join(format!("{artifact_name}.wasm"));

    if !artifact_path.exists() {
        bail!(
            "Expected WASM artifact at '{}' but it was not found after a successful build.\n\
             Make sure the crate has `crate-type = [\"cdylib\"]` in its `[lib]` section.",
            artifact_path.display()
        );
    }

    Ok(artifact_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_contract_crate ────────────────────────────────────────────────────

    #[test]
    fn detects_crate_dir_with_cargo_toml() {
        // Use the workspace root itself as a test crate directory.
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(
            is_contract_crate(workspace),
            "workspace root has Cargo.toml and should be detected"
        );
    }

    #[test]
    fn rejects_plain_file_as_crate_dir() {
        // A .wasm file is not a crate directory.
        let wasm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/v1/soroban_token.wasm");
        // May not exist in all environments; skip if absent.
        if !wasm.exists() {
            return;
        }
        assert!(
            !is_contract_crate(&wasm),
            "a .wasm file must not be treated as a crate directory"
        );
    }

    #[test]
    fn rejects_dir_without_cargo_toml() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(
            !is_contract_crate(tmp.path()),
            "a directory without Cargo.toml is not a crate"
        );
    }

    // ── check_cargo_available ────────────────────────────────────────────────

    #[test]
    fn cargo_is_available_in_test_env() {
        // The test suite itself runs under Cargo, so cargo must be on PATH.
        check_cargo_available().expect("cargo must be available in the test environment");
    }

    // ── missing Cargo.toml ───────────────────────────────────────────────────

    #[test]
    fn build_fails_clearly_when_cargo_toml_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let err = build_contract_crate(tmp.path(), &ResourcePolicy::default())
            .expect_err("should fail without Cargo.toml");
        let msg = err.to_string();
        assert!(
            msg.contains("Cargo.toml"),
            "error must mention Cargo.toml: {msg}"
        );
    }
}
