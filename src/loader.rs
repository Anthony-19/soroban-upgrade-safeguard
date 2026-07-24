use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;
use stellar_xdr::curr::{
    ContractExecutable, Hash, LedgerEntry, LedgerEntryData, LedgerKey, LedgerKeyContractCode,
    LedgerKeyContractData, Limits, ReadXdr, ScAddress, ScVal, WriteXdr,
};

use wasmparser::{Parser, Payload};

use crate::limits::{LimitError, ResourcePolicy};

/// Holds raw WASM bytes alongside the validated file path.
#[derive(Debug)]
pub struct WasmModule {
    pub path: String,
    pub bytes: Vec<u8>,
    /// SHA-256 hash of the WASM bytecode, verified against on-chain data
    /// (only populated when fetched from RPC).
    pub verified_hash: Option<[u8; 32]>,
}

/// A dedicated error type for cryptographic or payload integrity failures.
///
/// Returned instead of a generic `anyhow::Error` so callers can inspect the
/// kind of integrity failure without parsing error messages.
#[derive(Debug)]
pub struct IntegrityError {
    pub kind: IntegrityErrorKind,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityErrorKind {
    /// The computed SHA-256 hash of fetched WASM bytecode does not match the
    /// hash stored in the contract instance entry.
    HashMismatch,
    /// The ledger key returned by the RPC does not match the requested key.
    KeyMismatch,
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IntegrityError[{:?}]: {}", self.kind, self.details)
    }
}

impl std::error::Error for IntegrityError {}

/// Reads a WASM file from disk, validates it is a valid WASM binary,
/// and returns a `WasmModule` ready for further analysis.
pub fn load_wasm(path: &Path) -> Result<WasmModule> {
    if path.is_dir() {
        bail!("'{}' is a directory, not a WASM file", path.display());
    }

    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))?;

    if bytes.len() < 4 || &bytes[0..4] != b"\0asm" {
        bail!(
            "'{}' does not appear to be a valid WASM binary (bad magic bytes)",
            path.display()
        );
    }

    validate_wasm_structure(&bytes)
        .with_context(|| format!("WASM validation failed for '{}'", path.display()))?;

    Ok(WasmModule {
        path: path.to_string_lossy().into_owned(),
        bytes,
        verified_hash: None,
    })
}

fn validate_wasm_structure(bytes: &[u8]) -> Result<()> {
    let parser = Parser::new(0);
    for payload in parser.parse_all(bytes) {
        match payload.context("Malformed WASM payload encountered")? {
            Payload::Version { .. } => {}
            Payload::TypeSection(_) => {}
            Payload::FunctionSection(_) => {}
            Payload::TableSection(_) => {}
            Payload::MemorySection(_) => {}
            Payload::GlobalSection(_) => {}
            Payload::ExportSection(_) => {}
            Payload::ImportSection(_) => {}
            Payload::ElementSection(_) => {}
            Payload::DataSection(_) => {}
            Payload::CodeSectionStart { .. } => {}
            Payload::CodeSectionEntry(_) => {}
            Payload::CustomSection(_) => {}
            Payload::End(_) => {}
            _ => {}
        }
    }
    Ok(())
}

/// Fetches a deployed Soroban contract's WASM bytes from Stellar RPC by contract
/// ID, using the default [`ResourcePolicy`].
pub fn fetch_wasm_from_rpc(contract_id: &str, rpc_url: &str) -> Result<WasmModule> {
    fetch_wasm_from_rpc_with_policy(contract_id, rpc_url, &ResourcePolicy::default())
}

/// Fetches a deployed Soroban contract's WASM bytes from Stellar RPC by contract
/// ID, bounding XDR (de)serialization by `policy`.
///
/// RPC responses are attacker-influenced (the contract ID is arbitrary), so the
/// `LedgerEntry` payloads are decoded under `policy.xdr_limits()`: an oversized or
/// deeply nested entry fails with a [`LimitError`] instead of exhausting memory or
/// the stack. The returned WASM is validated structurally; its embedded spec is
/// subject to the same policy when later decoded by the caller.
pub fn fetch_wasm_from_rpc_with_policy(
    contract_id: &str,
    rpc_url: &str,
    policy: &ResourcePolicy,
) -> Result<WasmModule> {
    // 1. Parse contract_id using stellar_strkey
    let strkey = stellar_strkey::Strkey::from_string(contract_id)
        .map_err(|e| anyhow::anyhow!("Invalid contract ID '{}': {}", contract_id, e))?;

    let contract_bytes = match strkey {
        stellar_strkey::Strkey::Contract(c) => c.0,
        _ => bail!("Provided ID '{}' is not a valid contract ID", contract_id),
    };

    let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(Hash(contract_bytes)),
        key: ScVal::LedgerKeyContractInstance,
        durability: stellar_xdr::curr::ContractDataDurability::Persistent,
    });

    // 3. Serialize LedgerKey to Base64 with policy limits (for validation).
    let _key_b64 = ledger_key
        .to_xdr_base64(policy.xdr_limits())
        .map_err(|e| anyhow::anyhow!("Failed to serialize LedgerKey to base64: {}", e))?;

    // 4. Query getLedgerEntries RPC
    let response = query_rpc(
        rpc_url,
        "getLedgerEntries",
        serde_json::json!({
            "keys": [ledger_key
                .to_xdr_base64(Limits::none())
                .map_err(|e| anyhow::anyhow!("Failed to serialize LedgerKey: {}", e))?]
        }),
    )?;

    let entries = response["result"]["entries"]
        .as_array()
        .context("RPC response did not contain 'entries' array")?;

    let matched_entry = find_entry_by_key(entries, &ledger_key, "contract-instance lookup")?;

    let entry_xdr_b64 = matched_entry["xdr"]
        .as_str()
        .context("RPC response entry missing 'xdr' field")?;

    // 6. Deserialize LedgerEntry
    let entry = LedgerEntry::from_xdr_base64(entry_xdr_b64, policy.xdr_limits()).map_err(|e| {
        LimitError::from_xdr_error(&e, policy)
            .map(anyhow::Error::from)
            .unwrap_or_else(|| anyhow::anyhow!("Failed to deserialize LedgerEntry XDR: {}", e))
    })?;

    let contract_data = match entry.data {
        LedgerEntryData::ContractData(cd) => cd,
        _ => bail!("Unexpected ledger entry type returned for contract instance"),
    };

    let instance = match contract_data.val {
        ScVal::ContractInstance(inst) => inst,
        _ => bail!("Expected ScVal::ContractInstance in contract data"),
    };

    let wasm_hash = match instance.executable {
        ContractExecutable::Wasm(hash) => hash,
        ContractExecutable::StellarAsset => {
            bail!(
                "Contract '{}' is a built-in Stellar Asset contract and does not have WASM bytecode",
                contract_id
            );
        }
    };

    let code_ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: wasm_hash.clone(),
    });

    let _code_key_b64 = code_ledger_key
        .to_xdr_base64(policy.xdr_limits())
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to serialize ContractCode LedgerKey to base64: {}",
                e
            )
        })?;

    let code_response = query_rpc(
        rpc_url,
        "getLedgerEntries",
        serde_json::json!({
            "keys": [code_ledger_key
                .to_xdr_base64(Limits::none())
                .map_err(|e| anyhow::anyhow!("Failed to serialize code key: {}", e))?]
        }),
    )?;

    let code_entries = code_response["result"]["entries"]
        .as_array()
        .context("RPC response for contract code did not contain 'entries' array")?;

    let matched_code_entry =
        find_entry_by_key(code_entries, &code_ledger_key, "contract-code lookup")?;

    let code_entry_xdr_b64 = matched_code_entry["xdr"]
        .as_str()
        .context("RPC response code entry missing 'xdr' field")?;

    let code_entry = LedgerEntry::from_xdr_base64(code_entry_xdr_b64, policy.xdr_limits())
        .map_err(|e| {
            LimitError::from_xdr_error(&e, policy)
                .map(anyhow::Error::from)
                .unwrap_or_else(|| {
                    anyhow::anyhow!("Failed to deserialize ContractCode LedgerEntry XDR: {}", e)
                })
        })?;

    let contract_code = match code_entry.data {
        LedgerEntryData::ContractCode(code) => code,
        _ => bail!("Unexpected ledger entry type returned for contract code"),
    };

    let wasm_bytes = contract_code.code.to_vec();

    let computed_hash = Sha256::digest(&wasm_bytes);
    if computed_hash[..] != wasm_hash.0[..] {
        return Err(IntegrityError {
            kind: IntegrityErrorKind::HashMismatch,
            details: format!(
                "WASM hash mismatch for contract '{}': expected {}, computed {}",
                contract_id,
                hex::encode(wasm_hash.0),
                hex::encode(computed_hash),
            ),
        }
        .into());
    }

    if wasm_bytes.len() < 4 || &wasm_bytes[0..4] != b"\0asm" {
        bail!(
            "Fetched WASM for contract '{}' has invalid magic bytes",
            contract_id
        );
    }

    validate_wasm_structure(&wasm_bytes).with_context(|| {
        format!(
            "WASM validation failed for fetched contract '{}'",
            contract_id
        )
    })?;

    Ok(WasmModule {
        path: format!("stellar://{}", contract_id),
        bytes: wasm_bytes,
        verified_hash: Some(wasm_hash.0),
    })
}

/// Find and return the single RPC ledger-entry whose `"key"` base64 matches
/// `expected_key`, within the given JSON `entries` array.
///
/// # Errors
///
/// Returns an error if:
/// - `entries` is empty ("zero entries returned")
/// - No entry key matches — returns [`IntegrityError::KeyMismatch`] because the RPC
///   returning a non-matching key is a ledger-integrity violation, not a "not found"
/// - More than one entry matches ("share the same ledger key")
/// - An entry is missing its `"key"` field ("missing 'key'")
/// - An entry is missing its `"xdr"` field ("missing 'xdr'")
fn find_entry_by_key<'a>(
    entries: &'a [serde_json::Value],
    expected_key: &LedgerKey,
    context_label: &str,
) -> Result<&'a serde_json::Value> {
    if entries.is_empty() {
        anyhow::bail!(
            "{}: RPC returned zero entries for the ledger key",
            context_label
        );
    }

    let expected_b64 = expected_key
        .to_xdr_base64(Limits::none())
        .map_err(|e| anyhow::anyhow!("{}: failed to encode expected key: {}", context_label, e))?;

    let mut matches: Vec<&serde_json::Value> = Vec::new();
    for entry in entries {
        let entry_key_b64 = entry["key"]
            .as_str()
            .with_context(|| format!("{}: entry missing 'key' field", context_label))?;
        if entry_key_b64 == expected_b64 {
            // Also verify the xdr field is present.
            let _ = entry["xdr"]
                .as_str()
                .with_context(|| format!("{}: entry missing 'xdr' field", context_label))?;
            matches.push(entry);
        }
    }

    match matches.len() {
        0 => Err(IntegrityError {
            kind: IntegrityErrorKind::KeyMismatch,
            details: format!(
                "{}: no entry matches the requested ledger key",
                context_label
            ),
        }
        .into()),
        1 => Ok(matches[0]),
        _ => anyhow::bail!(
            "{}: {} entries share the same ledger key — response is ambiguous",
            context_label,
            matches.len()
        ),
    }
}

/// Validates an RPC URL for secure transport.
///
/// - Rejects non-`https` URLs unless `allow_http_local` is `true`.
/// - When `allow_http_local` is `true`, only `localhost` and `127.0.0.1` are
///   accepted for `http://` URLs.
/// - Rejects unknown/unexpected schemes.
pub fn validate_rpc_url(rpc_url: &str, allow_http_local: bool) -> Result<()> {
    if rpc_url.starts_with("https://") {
        return Ok(());
    }

    if let Some(rest) = rpc_url.strip_prefix("http://") {
        if !allow_http_local {
            bail!(
                "Insecure RPC URL scheme 'http' for '{}'. \
                 Use 'https://' for secure transport, or pass \
                 --allow-http-local for local development only.",
                rpc_url
            );
        }

        let host = rest.split('/').next().unwrap_or(rest);
        let host = host.split(':').next().unwrap_or(host);

        if host != "localhost" && host != "127.0.0.1" {
            bail!(
                "HTTP RPC URL '{}' is not allowed. \
                 --allow-http-local only permits localhost or 127.0.0.1.",
                rpc_url
            );
        }
        return Ok(());
    }

    bail!(
        "Unsupported RPC URL scheme in '{}'. Use 'https://'.",
        rpc_url
    )
}

/// Helper to execute JSON-RPC request to Stellar RPC.
/// Disables redirect following to prevent HTTPS-to-HTTP downgrade attacks.
fn query_rpc(rpc_url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    });

    let agent = ureq::AgentBuilder::new().redirects(0).build();

    let response: serde_json::Value = agent
        .post(rpc_url)
        .send_json(payload)
        .map_err(|e| anyhow::anyhow!("RPC request failed: {}", e))?
        .into_json()
        .map_err(|e| anyhow::anyhow!("Failed to parse RPC response: {}", e))?;

    if let Some(err) = response.get("error") {
        let msg = err["message"].as_str().unwrap_or("Unknown RPC error");
        let code = err["code"].as_i64().unwrap_or(0);
        bail!("RPC Error (code {}): {}", code, msg);
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::LedgerKeyContractData;

    #[test]
    fn test_validate_rpc_url_accepts_https() {
        assert!(validate_rpc_url("https://soroban-testnet.stellar.org", false).is_ok());
        assert!(validate_rpc_url("https://localhost:8080", true).is_ok());
    }

    #[test]
    fn test_validate_rpc_url_rejects_http_without_flag() {
        let err = validate_rpc_url("http://evil-rpc.example.com", false).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("Insecure"), "got: {}", msg);
    }

    #[test]
    fn test_validate_rpc_url_rejects_remote_http_even_with_flag() {
        let err = validate_rpc_url("http://evil-rpc.example.com", true).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("only permits localhost"), "got: {}", msg);
    }

    #[test]
    fn test_validate_rpc_url_accepts_local_http_with_flag() {
        assert!(validate_rpc_url("http://localhost:8080", true).is_ok());
        assert!(validate_rpc_url("http://127.0.0.1:12345", true).is_ok());
    }

    #[test]
    fn test_validate_rpc_url_rejects_unsupported_scheme() {
        let err = validate_rpc_url("ftp://rpc.example.com", false).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("Unsupported"), "got: {}", msg);
    }

    fn dummy_ledger_key() -> LedgerKey {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(Hash([0u8; 32])),
            key: ScVal::LedgerKeyContractInstance,
            durability: stellar_xdr::curr::ContractDataDurability::Persistent,
        })
    }

    fn key_b64(key: &LedgerKey) -> String {
        key.to_xdr_base64(Limits::none()).unwrap()
    }

    fn make_entry(key_b64: &str, xdr_b64: &str) -> serde_json::Value {
        serde_json::json!({
            "key": key_b64,
            "xdr": xdr_b64,
        })
    }

    #[test]
    fn test_find_entry_by_key_matches_correctly() {
        let key = dummy_ledger_key();
        let b64 = key_b64(&key);
        let entries = vec![make_entry(&b64, "dummy")];

        let result = find_entry_by_key(&entries, &key, "test");
        assert!(result.is_ok(), "should find matching entry: {:?}", result);
    }

    #[test]
    fn test_find_entry_by_key_rejects_empty_entries() {
        let key = dummy_ledger_key();
        let entries = vec![];

        let err = find_entry_by_key(&entries, &key, "test").unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("zero entries"), "got: {}", msg);
    }

    #[test]
    fn test_find_entry_by_key_rejects_mismatched_key() {
        let key = dummy_ledger_key();
        let other_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(Hash([1u8; 32])),
            key: ScVal::LedgerKeyContractInstance,
            durability: stellar_xdr::curr::ContractDataDurability::Persistent,
        });
        let other_b64 = key_b64(&other_key);
        let entries = vec![make_entry(&other_b64, "dummy")];

        let err = find_entry_by_key(&entries, &key, "test").unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("no entry matches"), "got: {}", msg);
    }

    #[test]
    fn test_find_entry_by_key_rejects_duplicate_matches() {
        let key = dummy_ledger_key();
        let b64 = key_b64(&key);
        let entries = vec![make_entry(&b64, "first"), make_entry(&b64, "second")];

        let err = find_entry_by_key(&entries, &key, "test").unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("share the same ledger key"), "got: {}", msg);
    }

    #[test]
    fn test_find_entry_by_key_rejects_missing_key_field() {
        let key = dummy_ledger_key();
        let entries = vec![serde_json::json!({"xdr": "dummy"})];

        let err = find_entry_by_key(&entries, &key, "test").unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("missing 'key'"), "got: {}", msg);
    }

    #[test]
    fn test_find_entry_by_key_rejects_missing_xdr_field() {
        let key = dummy_ledger_key();
        let b64 = key_b64(&key);
        let entries = vec![serde_json::json!({"key": b64})];

        let err = find_entry_by_key(&entries, &key, "test").unwrap_err();
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("missing 'xdr'") || msg.contains("missing 'key'"),
            "got: {}",
            msg
        );
    }

    #[test]
    fn test_load_wasm_rejects_directory() {
        let dir = std::env::temp_dir().join("soroban-upgrade-safeguard-test-dir");
        std::fs::create_dir_all(&dir).unwrap();

        let err = load_wasm(&dir).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("is a directory"), "got: {}", msg);

        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn test_load_wasm_reports_missing_file() {
        let path = std::env::temp_dir().join("soroban-upgrade-safeguard-does-not-exist.wasm");
        let _ = std::fs::remove_file(&path);

        let err = load_wasm(&path).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains(&path.display().to_string()), "got: {}", msg);
    }

    #[test]
    fn test_wasm_module_default_verified_hash_none() {
        let module = WasmModule {
            path: "/tmp/test.wasm".into(),
            bytes: vec![0x00, 0x61, 0x73, 0x6d],
            verified_hash: None,
        };
        assert!(module.verified_hash.is_none());
    }
}
