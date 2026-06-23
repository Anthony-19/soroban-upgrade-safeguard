//! Integration tests for the `--contract-id` / `--rpc-url` RPC fetch mode.
//!
//! These tests spin up a lightweight HTTP mock server that emulates the
//! Stellar RPC `getLedgerEntries` endpoint, returning pre-built XDR payloads
//! so we can exercise the full fetch→parse→compare pipeline without touching
//! a real network.

use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::thread;

use stellar_xdr::curr::{
    ContractCodeEntry, ContractDataDurability, ContractDataEntry, ContractExecutable,
    ExtensionPoint, Hash, LedgerEntry, LedgerEntryData, LedgerEntryExt, Limits, ScAddress,
    ScContractInstance, ScVal, WriteXdr,
};

/// Contract ID used in tests (a valid C... strkey for 32 zero bytes).
const TEST_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

/// Path to a fixture WASM under `tests/wasm/`.
fn wasm_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Read a fixture WASM file's raw bytes.
fn wasm_bytes(name: &str) -> Vec<u8> {
    std::fs::read(wasm_fixture(name)).expect("failed to read WASM fixture")
}

/// Build LedgerEntry XDR (base64) for the contract instance response.
/// Contains the WASM hash pointing at the given code bytes.
fn build_instance_entry_xdr(wasm_hash: &[u8; 32]) -> String {
    let entry = LedgerEntry {
        last_modified_ledger_seq: 100,
        data: LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(Hash([0u8; 32])),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::Wasm(Hash(*wasm_hash)),
                storage: None,
            }),
        }),
        ext: LedgerEntryExt::V0,
    };
    entry
        .to_xdr_base64(Limits::none())
        .expect("failed to encode instance entry")
}

/// Build LedgerEntry XDR (base64) for the contract code response.
fn build_code_entry_xdr(wasm_hash: &[u8; 32], code: &[u8]) -> String {
    let entry = LedgerEntry {
        last_modified_ledger_seq: 100,
        data: LedgerEntryData::ContractCode(ContractCodeEntry {
            ext: stellar_xdr::curr::ContractCodeEntryExt::V0,
            hash: Hash(*wasm_hash),
            code: code.try_into().expect("WASM code too large for BytesM"),
        }),
        ext: LedgerEntryExt::V0,
    };
    entry
        .to_xdr_base64(Limits::none())
        .expect("failed to encode code entry")
}

/// A tiny HTTP server that handles exactly two sequential `getLedgerEntries`
/// requests and returns pre-canned JSON-RPC responses.
///
/// Returns the bound address (e.g. "127.0.0.1:PORT").
fn start_mock_rpc(instance_xdr: String, code_xdr: String) -> (String, Arc<TcpListener>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock server");
    let addr = listener.local_addr().unwrap().to_string();
    let listener = Arc::new(listener);
    let listener_clone = Arc::clone(&listener);

    thread::spawn(move || {
        // Handle exactly 2 requests (instance lookup, then code lookup)
        for xdr in [instance_xdr, code_xdr].iter() {
            let (mut stream, _) = listener_clone.accept().expect("failed to accept");

            // Read the full HTTP request (we don't need to parse it carefully)
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).expect("failed to read request");
            let _request = String::from_utf8_lossy(&buf[..n]);

            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "latestLedger": 200,
                    "entries": [{
                        "key": "ignored",
                        "xdr": xdr,
                        "lastModifiedLedgerSeq": 100
                    }]
                }
            });
            let body_str = serde_json::to_string(&body).unwrap();

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body_str.len(),
                body_str
            );
            stream.write_all(response.as_bytes()).expect("failed to write response");
            stream.flush().expect("failed to flush");
        }
    });

    (addr, listener)
}

/// Start a mock server that returns empty entries (contract not found).
fn start_mock_rpc_not_found() -> (String, Arc<TcpListener>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock server");
    let addr = listener.local_addr().unwrap().to_string();
    let listener = Arc::new(listener);
    let listener_clone = Arc::clone(&listener);

    thread::spawn(move || {
        let (mut stream, _) = listener_clone.accept().expect("failed to accept");
        let mut buf = [0u8; 8192];
        let _ = stream.read(&mut buf).expect("failed to read request");

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": 200,
                "entries": []
            }
        });
        let body_str = serde_json::to_string(&body).unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body_str.len(),
            body_str
        );
        stream.write_all(response.as_bytes()).expect("failed to write response");
        stream.flush().expect("failed to flush");
    });

    (addr, listener)
}

#[test]
fn rpc_fetch_compares_on_chain_against_local() {
    // Use v1.wasm as the "on-chain" contract and v2.wasm as the "candidate"
    let code = wasm_bytes("v1.wasm");
    let wasm_hash: [u8; 32] = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        code.hash(&mut hasher);
        let h = hasher.finish();
        // Just use the hash bytes repeated to fill 32 bytes
        let mut arr = [0u8; 32];
        arr[..8].copy_from_slice(&h.to_le_bytes());
        arr
    };

    let instance_xdr = build_instance_entry_xdr(&wasm_hash);
    let code_xdr = build_code_entry_xdr(&wasm_hash, &code);
    let (addr, _listener) = start_mock_rpc(instance_xdr, code_xdr);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--contract-id",
            TEST_CONTRACT_ID,
            "--rpc-url",
            &format!("http://{}", addr),
        ])
        .arg(wasm_fixture("v2.wasm"))
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout not UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");

    let json: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}\n---stderr---\n{stderr}")
    });

    // v1 vs v2 should produce a breaking report
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert!(json["counts"]["critical"].as_u64().unwrap() >= 1);

    // The exit code must be 1 for a breaking upgrade
    let code = output.status.code().expect("no exit code");
    assert_eq!(code, 1, "breaking upgrade must exit 1");
}

#[test]
fn rpc_fetch_safe_comparison() {
    // Use v1.wasm as both "on-chain" and "candidate" — should be safe
    let code = wasm_bytes("v1.wasm");
    let wasm_hash: [u8; 32] = {
        let mut arr = [0u8; 32];
        arr[0] = 42; // arbitrary distinct hash
        arr
    };

    let instance_xdr = build_instance_entry_xdr(&wasm_hash);
    let code_xdr = build_code_entry_xdr(&wasm_hash, &code);
    let (addr, _listener) = start_mock_rpc(instance_xdr, code_xdr);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--contract-id",
            TEST_CONTRACT_ID,
            "--rpc-url",
            &format!("http://{}", addr),
        ])
        .arg(wasm_fixture("v1.wasm")) // same as on-chain
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout not UTF-8");
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}"));

    assert_eq!(json["is_safe"], Value::Bool(true));
    assert_eq!(output.status.code().unwrap(), 0);
}

#[test]
fn rpc_fetch_contract_not_found_produces_clear_error() {
    let (addr, _listener) = start_mock_rpc_not_found();

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--contract-id",
            TEST_CONTRACT_ID,
            "--rpc-url",
            &format!("http://{}", addr),
        ])
        .arg(wasm_fixture("v1.wasm"))
        .output()
        .expect("failed to run binary");

    let code = output.status.code().unwrap();
    assert_ne!(code, 0, "not-found must produce a non-zero exit");

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.contains("not found") || stderr.contains("not found on-chain"),
        "error message should mention 'not found', got: {stderr}"
    );
}

#[test]
fn rpc_fetch_network_failure_produces_clear_error() {
    // Point at a port that nothing is listening on
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--contract-id",
            TEST_CONTRACT_ID,
            "--rpc-url",
            "http://127.0.0.1:1", // almost certainly nobody is listening here
        ])
        .arg(wasm_fixture("v1.wasm"))
        .output()
        .expect("failed to run binary");

    let code = output.status.code().unwrap();
    assert_ne!(code, 0, "network failure must produce a non-zero exit");

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.contains("RPC request failed") || stderr.contains("Connection refused"),
        "error message should mention RPC failure, got: {stderr}"
    );
}

#[test]
fn local_two_file_mode_still_works() {
    // Smoke test: the original two-file positional usage is unchanged
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm_fixture("v1.wasm"))
        .arg(wasm_fixture("v2.wasm"))
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout not UTF-8");
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}"));

    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(output.status.code().unwrap(), 1);
}
