//! Integration tests for the `extract` subcommand.
//!
//! These run the compiled binary against the checked-in WASM fixtures, which is
//! how a developer inspecting a build or a pipeline archiving one would use it.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

/// Run `extract` on a fixture, returning (stdout, exit code).
fn extract(args: &[&str]) -> (String, i32) {
    let output = bin()
        .arg("extract")
        .args(args)
        .output()
        .expect("failed to run binary");

    (
        String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        output.status.code().expect("process terminated by signal"),
    )
}

fn extract_json(fixture: &str) -> Value {
    let path = wasm(fixture);
    let (stdout, code) = extract(&[path.to_str().unwrap()]);
    assert_eq!(code, 0, "extract must succeed on a valid fixture");
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}"))
}

#[test]
fn extract_emits_the_decoded_spec_as_json() {
    let json = extract_json("v1.wasm");

    assert_eq!(json["spec_schema_version"], 1);
    assert_eq!(json["tool_version"], env!("CARGO_PKG_VERSION"));
    assert!(json["source"].as_str().unwrap().ends_with("v1.wasm"));

    // The fixture declares functions and user-defined types; the point of the
    // subcommand is that all of them show up without a second tool.
    let functions = json["functions"].as_array().expect("functions array");
    assert!(
        !functions.is_empty(),
        "fixture should expose at least one function"
    );
    for function in functions {
        assert!(function["name"].is_string());
        assert!(function["inputs"].is_array());
        assert!(function["outputs"].is_array());
    }

    for key in ["structs", "enums", "unions", "error_enums"] {
        assert!(json[key].is_array(), "{key} must always be an array");
    }
}

#[test]
fn extract_includes_the_interface_hash() {
    let json = extract_json("v1.wasm");
    let hash = json["interface_hash"].as_str().expect("interface_hash");

    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn extract_includes_env_metadata() {
    let json = extract_json("v1.wasm");
    assert!(
        json["env_meta"]["protocol_version"].is_number(),
        "the fixture carries contractenvmetav0, so it must be reported"
    );
}

#[test]
fn extract_types_are_structurally_tagged() {
    let json = extract_json("v1.wasm");
    let functions = json["functions"].as_array().unwrap();

    // Every parameter type must carry a `kind` discriminator rather than being
    // a bare display string, so consumers can tell a UDT from a primitive.
    let mut saw_a_type = false;
    for function in functions {
        for input in function["inputs"].as_array().unwrap() {
            assert!(
                input["type"]["kind"].is_string(),
                "type must be tagged: {:?}",
                input["type"]
            );
            saw_a_type = true;
        }
    }
    assert!(saw_a_type, "fixture should have at least one parameter");
}

#[test]
fn extract_output_is_deterministic() {
    let first = extract_json("v1.wasm");
    let second = extract_json("v1.wasm");
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&second).unwrap(),
        "repeated extractions of the same build must be byte-identical"
    );
}

#[test]
fn extract_hash_only_prints_just_the_hash() {
    let path = wasm("v1.wasm");
    let (stdout, code) = extract(&[path.to_str().unwrap(), "--hash-only"]);

    assert_eq!(code, 0);
    let hash = stdout.trim();
    assert_eq!(
        stdout,
        format!("{hash}\n"),
        "--hash-only output must be exactly the digest and a newline"
    );
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn hash_only_agrees_with_the_full_extraction() {
    let path = wasm("v1.wasm");
    let (stdout, _) = extract(&[path.to_str().unwrap(), "--hash-only"]);
    assert_eq!(stdout.trim(), extract_json("v1.wasm")["interface_hash"]);
}

#[test]
fn different_interfaces_hash_differently() {
    let v1 = extract_json("v1.wasm")["interface_hash"].clone();
    let v2 = extract_json("v2.wasm")["interface_hash"].clone();
    assert_ne!(
        v1, v2,
        "the fixtures differ in their interface, so the hashes must differ"
    );
}

#[test]
fn extract_without_a_source_fails_with_guidance() {
    let output = bin().arg("extract").output().expect("failed to run binary");
    assert_ne!(output.status.code(), Some(0));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Missing WASM path"),
        "error should say what is missing, got: {stderr}"
    );
}

#[test]
fn extract_rejects_a_non_wasm_file() {
    let output = bin()
        .arg("extract")
        .arg(file!())
        .output()
        .expect("failed to run binary");
    assert_ne!(
        output.status.code(),
        Some(0),
        "a source file is not a WASM module"
    );
}

// --- The four pre-existing usage modes must be untouched ---------------------

#[test]
fn the_four_original_usage_modes_still_appear_in_help() {
    let output = bin().arg("--help").output().expect("failed to run binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    for mode in [
        "soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>",
        "--contract-id <ID> --rpc-url <URL> <NEW_WASM>",
        "--manifest <MANIFEST_PATH>",
        "--old-dir <OLD_DIR> --new-dir <NEW_DIR>",
    ] {
        assert!(stdout.contains(mode), "usage line missing: {mode}");
    }
}

#[test]
fn the_local_pair_mode_still_works() {
    // Adding subcommands must not change how two positional WASM paths parse.
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: Value = serde_json::from_str(&stdout).expect("still emits a JSON report");
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(output.status.code(), Some(1));
}
