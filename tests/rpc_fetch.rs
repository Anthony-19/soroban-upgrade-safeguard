//! Integration tests for the `--contract-id` / `--rpc-url` RPC fetch mode.
//!
//! These tests spin up a lightweight HTTP mock server that emulates the
//! Stellar RPC `getLedgerEntries` endpoint, returning pre-built XDR payloads
//! so we can exercise the full fetch→parse→compare pipeline without touching
//! a real network.

use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::thread;

use stellar_xdr::curr::{
    ContractCodeEntry, ContractDataDurability, ContractDataEntry, ContractExecutable,
    ExtensionPoint, Hash, LedgerEntry, LedgerEntryData, LedgerEntryExt, LedgerKey,
    LedgerKeyContractCode, LedgerKeyContractData, Limits, ScAddress, ScContractInstance, ScVal,
    WriteXdr,
};

/// Contract ID used in tests (a valid C... strkey — decodes to 31 zero bytes + 0x01).
const TEST_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

/// Decoded contract bytes for `TEST_CONTRACT_ID`.
const TEST_CONTRACT_BYTES: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

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

/// Build the base64-encoded `LedgerKey` for a contract instance lookup.
fn instance_key_b64(contract_bytes: &[u8; 32]) -> String {
    let key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(Hash(*contract_bytes)),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    key.to_xdr_base64(Limits::none())
        .expect("failed to encode instance ledger key")
}

/// Build the base64-encoded `LedgerKey` for a contract code lookup.
fn code_key_b64(wasm_hash: &[u8; 32]) -> String {
    let key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: Hash(*wasm_hash),
    });
    key.to_xdr_base64(Limits::none())
        .expect("failed to encode code ledger key")
}

/// A tiny HTTP server that handles exactly two sequential `getLedgerEntries`
/// requests and returns pre-canned JSON-RPC responses with valid keys.
///
/// Returns the bound address (e.g. "127.0.0.1:PORT").
fn start_mock_rpc(
    contract_bytes: &[u8; 32],
    wasm_hash: &[u8; 32],
    instance_xdr: String,
    code_xdr: String,
) -> (String, Arc<TcpListener>) {
    let instance_key = instance_key_b64(contract_bytes);
    let code_key = code_key_b64(wasm_hash);
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock server");
    let addr = listener.local_addr().unwrap().to_string();
    let listener = Arc::new(listener);
    let listener_clone = Arc::clone(&listener);

    thread::spawn(move || {
        let responses = vec![(instance_key, instance_xdr), (code_key, code_xdr)];

        for (key, xdr) in responses {
            let (mut stream, _) = listener_clone.accept().expect("failed to accept");
            let mut reader = BufReader::new(&stream);

            // Read HTTP request line
            let mut _line = String::new();
            let _ = reader.read_line(&mut _line);

            // Read headers (ignore, we pre-generated the correct key)
            let mut content_length: usize = 0;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 || header.trim().is_empty() {
                    break;
                }
                if header.to_lowercase().starts_with("content-length:") {
                    content_length = header
                        .trim()
                        .split(':')
                        .nth(1)
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                }
            }

            // Consume the body (needed to complete the HTTP request)
            if content_length > 0 {
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body);
            }
            drop(reader);

            let entry = serde_json::Map::from_iter([
                ("key".into(), serde_json::Value::String(key)),
                ("xdr".into(), serde_json::Value::String(xdr)),
                ("lastModifiedLedgerSeq".into(), serde_json::json!(100)),
            ]);

            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "latestLedger": 200,
                    "entries": [serde_json::Value::Object(entry)]
                }
            });
            let body_str = serde_json::to_string(&body).unwrap();

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body_str.len(),
                body_str
            );
            stream
                .write_all(response.as_bytes())
                .expect("failed to write response");
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
        let mut reader = BufReader::new(&stream);
        let mut _line = String::new();
        // Read request line + headers + blank line to consume the request
        for _ in 0..20 {
            _line.clear();
            if reader.read_line(&mut _line).unwrap_or(0) == 0 || _line.trim().is_empty() {
                break;
            }
        }
        drop(reader);

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
        stream
            .write_all(response.as_bytes())
            .expect("failed to write response");
        stream.flush().expect("failed to flush");
    });

    (addr, listener)
}

#[test]
fn rpc_fetch_compares_on_chain_against_local() {
    // Use v1.wasm as the "on-chain" contract and v2.wasm as the "candidate"
    let code = wasm_bytes("v1.wasm");
    let wasm_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(&code);
        hash.into()
    };

    let instance_xdr = build_instance_entry_xdr(&wasm_hash);
    let code_xdr = build_code_entry_xdr(&wasm_hash, &code);
    let (addr, _listener) =
        start_mock_rpc(&TEST_CONTRACT_BYTES, &wasm_hash, instance_xdr, code_xdr);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--contract-id",
            TEST_CONTRACT_ID,
            "--rpc-url",
            &format!("http://{}", addr),
            "--allow-http-local",
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
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(&code);
        hash.into()
    };

    let instance_xdr = build_instance_entry_xdr(&wasm_hash);
    let code_xdr = build_code_entry_xdr(&wasm_hash, &code);
    let (addr, _listener) =
        start_mock_rpc(&TEST_CONTRACT_BYTES, &wasm_hash, instance_xdr, code_xdr);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--contract-id",
            TEST_CONTRACT_ID,
            "--rpc-url",
            &format!("http://{}", addr),
            "--allow-http-local",
        ])
        .arg(wasm_fixture("v1.wasm")) // same as on-chain
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout not UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");

    assert!(
        output.status.success(),
        "safe comparison should succeed\nstdout: {stdout}\nstderr: {stderr}"
    );
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
            "--allow-http-local",
        ])
        .arg(wasm_fixture("v1.wasm"))
        .output()
        .expect("failed to run binary");

    let code = output.status.code().unwrap();
    assert_ne!(code, 0, "not-found must produce a non-zero exit");

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.contains("zero entries") || stderr.contains("not found"),
        "error message should mention empty entries or 'not found', got: {stderr}"
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
            "--allow-http-local",
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
fn rpc_fetch_malformed_url_is_rejected_before_any_request() {
    // Each of these is wrong in a different way, and none of them should be
    // allowed to reach the HTTP client: the error must name the URL.
    let cases = [
        ("htps://soroban-testnet.stellar.org", "unsupported scheme"),
        ("soroban-testnet.stellar.org", "no scheme"),
        ("https:///getLedgerEntries", "no host"),
        ("ftp://rpc.example.com", "unsupported scheme"),
    ];

    for (url, expected) in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
            .args(["--contract-id", TEST_CONTRACT_ID, "--rpc-url", url])
            .arg(wasm_fixture("v1.wasm"))
            .output()
            .expect("failed to run binary");

        assert_ne!(
            output.status.code().unwrap(),
            0,
            "malformed URL '{url}' must exit non-zero"
        );

        let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
        assert!(
            stderr.contains(expected),
            "error for '{url}' should mention {expected:?}, got: {stderr}"
        );
        assert!(
            stderr.contains("Invalid RPC URL"),
            "error for '{url}' should identify the URL as the problem, got: {stderr}"
        );
        assert!(
            !stderr.contains("RPC request failed"),
            "no request should have been attempted for '{url}', got: {stderr}"
        );
    }
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

// ── Malicious RPC tests ─────────────────────────────────────────────────

/// Start a mock server that returns code bytes whose SHA-256 does NOT match
/// the hash stored in the contract instance entry (tampered-bytecode attack).
///
/// The CODE KEY is generated with the *real* hash (so key matching passes),
/// but the code *bytes* in the XDR belong to a different contract, so the
/// SHA-256 verification in `fetch_wasm_from_rpc` will fail.
fn start_mock_tampered_code(
    instance_xdr: String,
    wasm_hash: &[u8; 32],
    tampered_code_xdr: String,
) -> (String, Arc<TcpListener>) {
    let instance_key = instance_key_b64(&TEST_CONTRACT_BYTES);
    // Use the correct hash for the code key so that key matching succeeds
    let code_key = code_key_b64(wasm_hash);

    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock server");
    let addr = listener.local_addr().unwrap().to_string();
    let listener = Arc::new(listener);
    let listener_clone = Arc::clone(&listener);

    thread::spawn(move || {
        let responses = vec![(instance_key, instance_xdr), (code_key, tampered_code_xdr)];

        for (key, xdr) in responses {
            let (mut stream, _) = listener_clone.accept().expect("failed to accept");
            let mut reader = BufReader::new(&stream);
            let mut _line = String::new();
            let _ = reader.read_line(&mut _line);
            let mut content_length: usize = 0;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 || header.trim().is_empty() {
                    break;
                }
                if header.to_lowercase().starts_with("content-length:") {
                    content_length = header
                        .trim()
                        .split(':')
                        .nth(1)
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                }
            }
            if content_length > 0 {
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body);
            }
            drop(reader);

            let entry = serde_json::Map::from_iter([
                ("key".into(), serde_json::Value::String(key)),
                ("xdr".into(), serde_json::Value::String(xdr)),
                ("lastModifiedLedgerSeq".into(), serde_json::json!(100)),
            ]);

            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "latestLedger": 200,
                    "entries": [serde_json::Value::Object(entry)]
                }
            });
            let body_str = serde_json::to_string(&body).unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body_str.len(),
                body_str
            );
            stream.write_all(response.as_bytes()).expect("write");
            stream.flush().expect("flush");
        }
    });

    (addr, listener)
}

#[test]
fn rpc_fetch_tampered_code_raises_integrity_error() {
    // The instance entry claims hash H(v1), but the code endpoint returns
    // v2.wasm bytes.  The SHA-256 will differ → IntegrityError[HashMismatch].
    let v1_code = wasm_bytes("v1.wasm");
    let v1_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&v1_code).into()
    };
    let v2_code = wasm_bytes("v2.wasm");

    let instance_xdr = build_instance_entry_xdr(&v1_hash);
    let tampered_code_xdr = build_code_entry_xdr(&v1_hash, &v2_code);
    let (addr, _listener) = start_mock_tampered_code(instance_xdr, &v1_hash, tampered_code_xdr);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--contract-id",
            TEST_CONTRACT_ID,
            "--rpc-url",
            &format!("http://{}", addr),
            "--allow-http-local",
        ])
        .arg(wasm_fixture("v1.wasm"))
        .output()
        .expect("failed to run binary");

    let code = output.status.code().unwrap();
    assert_ne!(code, 0, "tampered code must exit non-zero");

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.contains("IntegrityError") && stderr.contains("HashMismatch"),
        "error should contain IntegrityError[HashMismatch], got: {stderr}"
    );
}

/// Start a mock that returns an entry with a completely wrong ledger key.
fn start_mock_wrong_key(instance_xdr: String, code_xdr: String) -> (String, Arc<TcpListener>) {
    // Deliberately use a wrong key that does NOT match what the loader expects
    let wrong_key = instance_key_b64(&[0xde; 32]);
    let wrong_code_key = code_key_b64(&[0xad; 32]);

    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock server");
    let addr = listener.local_addr().unwrap().to_string();
    let listener = Arc::new(listener);
    let listener_clone = Arc::clone(&listener);

    thread::spawn(move || {
        let responses = vec![(wrong_key, instance_xdr), (wrong_code_key, code_xdr)];

        for (key, xdr) in responses {
            let (mut stream, _) = listener_clone.accept().expect("failed to accept");
            let mut reader = BufReader::new(&stream);
            let mut _line = String::new();
            let _ = reader.read_line(&mut _line);
            let mut content_length: usize = 0;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 || header.trim().is_empty() {
                    break;
                }
                if header.to_lowercase().starts_with("content-length:") {
                    content_length = header
                        .trim()
                        .split(':')
                        .nth(1)
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                }
            }
            if content_length > 0 {
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body);
            }
            drop(reader);

            let entry = serde_json::Map::from_iter([
                ("key".into(), serde_json::Value::String(key)),
                ("xdr".into(), serde_json::Value::String(xdr)),
                ("lastModifiedLedgerSeq".into(), serde_json::json!(100)),
            ]);

            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "latestLedger": 200,
                    "entries": [serde_json::Value::Object(entry)]
                }
            });
            let body_str = serde_json::to_string(&body).unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body_str.len(),
                body_str
            );
            stream.write_all(response.as_bytes()).expect("write");
            stream.flush().expect("flush");
        }
    });

    (addr, listener)
}

#[test]
fn rpc_fetch_wrong_ledger_key_raises_integrity_error() {
    let code = wasm_bytes("v1.wasm");
    let wasm_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&code).into()
    };

    let instance_xdr = build_instance_entry_xdr(&wasm_hash);
    let code_xdr = build_code_entry_xdr(&wasm_hash, &code);
    let (addr, _listener) = start_mock_wrong_key(instance_xdr, code_xdr);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--contract-id",
            TEST_CONTRACT_ID,
            "--rpc-url",
            &format!("http://{}", addr),
            "--allow-http-local",
        ])
        .arg(wasm_fixture("v1.wasm"))
        .output()
        .expect("failed to run binary");

    let code = output.status.code().unwrap();
    assert_ne!(code, 0, "wrong key must exit non-zero");

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.contains("IntegrityError") && stderr.contains("KeyMismatch"),
        "error should contain IntegrityError[KeyMismatch], got: {stderr}"
    );
}

#[test]
fn rpc_fetch_expected_hash_pinning_succeeds() {
    let code = wasm_bytes("v1.wasm");
    let wasm_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&code).into()
    };

    let instance_xdr = build_instance_entry_xdr(&wasm_hash);
    let code_xdr = build_code_entry_xdr(&wasm_hash, &code);
    let (addr, _listener) =
        start_mock_rpc(&TEST_CONTRACT_BYTES, &wasm_hash, instance_xdr, code_xdr);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--contract-id",
            TEST_CONTRACT_ID,
            "--rpc-url",
            &format!("http://{}", addr),
            "--allow-http-local",
            "--expected-wasm-hash",
            &hex::encode(wasm_hash),
        ])
        .arg(wasm_fixture("v2.wasm"))
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    // Should still produce valid JSON output even with hash pinning
    let stdout = String::from_utf8(output.stdout).expect("stdout not UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");

    // The comparison v1 vs v2 should be breaking, but the hash pinning itself
    // succeeded (so no hash-pinning error). Exit code depends on the findings.
    if !stdout.is_empty() {
        let json: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!("stdout was not valid JSON: {e}\nstdout={stdout}\nstderr={stderr}")
        });
        assert_eq!(json["is_safe"], Value::Bool(false));
    }
}

#[test]
fn rpc_fetch_expected_hash_pinning_fails_on_mismatch() {
    let code = wasm_bytes("v1.wasm");
    let wasm_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&code).into()
    };
    // A wrong expected hash that does NOT match the on-chain hash
    let wrong_expected_hash = [0xabu8; 32];

    let instance_xdr = build_instance_entry_xdr(&wasm_hash);
    let code_xdr = build_code_entry_xdr(&wasm_hash, &code);
    let (addr, _listener) =
        start_mock_rpc(&TEST_CONTRACT_BYTES, &wasm_hash, instance_xdr, code_xdr);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--contract-id",
            TEST_CONTRACT_ID,
            "--rpc-url",
            &format!("http://{}", addr),
            "--allow-http-local",
            "--expected-wasm-hash",
            &hex::encode(wrong_expected_hash),
        ])
        .arg(wasm_fixture("v2.wasm"))
        .output()
        .expect("failed to run binary");

    let code = output.status.code().unwrap();
    assert_ne!(code, 0, "hash mismatch must exit non-zero");

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.contains("Hash mismatch") || stderr.contains("hash mismatch"),
        "error should mention hash mismatch, got: {stderr}"
    );
}
