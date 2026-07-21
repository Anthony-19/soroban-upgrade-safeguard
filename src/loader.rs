use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;
use stellar_xdr::curr::{
    ContractExecutable, Hash, LedgerEntry, LedgerEntryData, LedgerKey, LedgerKeyContractCode,
    LedgerKeyContractData, Limits, ReadXdr, ScAddress, ScVal, WriteXdr,
};
use wasmparser::{Parser, Payload};

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
    if !path.exists() {
        bail!("File not found: {}", path.display());
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

/// Scans a JSON-RPC `entries` array and returns the entry whose `key` field
/// matches the XDR-base64 encoding of `expected_key`.
fn find_entry_by_key<'a>(
    entries: &'a [serde_json::Value],
    expected_key: &LedgerKey,
    context: &str,
) -> Result<&'a serde_json::Value> {
    if entries.is_empty() {
        bail!("{}: RPC response returned zero entries", context);
    }

    let expected_b64 = expected_key
        .to_xdr_base64(Limits::none())
        .map_err(|e| anyhow::anyhow!("{}: failed to serialize expected key: {}", context, e))?;

    let mut matched: Vec<&serde_json::Value> = Vec::new();

    for entry in entries {
        let key_b64 = entry["key"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{}: RPC entry missing 'key' field", context))?;

        let _xdr_b64 = entry["xdr"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{}: RPC entry missing 'xdr' field", context))?;

        if key_b64 == expected_b64 {
            matched.push(entry);
        }
    }

    if matched.is_empty() {
        return Err(IntegrityError {
            kind: IntegrityErrorKind::KeyMismatch,
            details: format!(
                "{}: no entry matches the expected ledger key (possible RPC manipulation)",
                context
            ),
        }
        .into());
    }

    if matched.len() > 1 {
        bail!(
            "{}: {} entries share the same ledger key (possible RPC manipulation)",
            context,
            matched.len()
        );
    }

    Ok(matched[0])
}

/// Fetches a deployed Soroban contract's WASM bytes from Stellar RPC by contract ID.
///
/// # Zero-Trust Pipeline
///
/// 1. Parses and validates the contract ID via `stellar_strkey`.
/// 2. Builds the expected `LedgerKey` for the contract instance.
/// 3. Queries `getLedgerEntries` and defensively validates that exactly one
///    entry matches the requested key — rejects empty, duplicate, or mismatched
///    payloads.
/// 4. Extracts the `ContractExecutable::Wasm` hash from the instance.
/// 5. Queries the contract-code sub-entry using the advertised hash.
/// 6. Reconcilies the returned key against the expected code `LedgerKey`.
/// 7. Computes the SHA-256 of the fetched bytecode and compares it against the
///    hash from step 4 — aborts on mismatch with an `IntegrityError`.
pub fn fetch_wasm_from_rpc(
    contract_id: &str,
    rpc_url: &str,
    allow_http_local: bool,
) -> Result<WasmModule> {
    validate_rpc_url(rpc_url, allow_http_local).context("RPC transport security check failed")?;

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

    let entry = LedgerEntry::from_xdr_base64(entry_xdr_b64, Limits::none())
        .map_err(|e| anyhow::anyhow!("Failed to deserialize LedgerEntry XDR: {}", e))?;

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

    let code_entry =
        LedgerEntry::from_xdr_base64(code_entry_xdr_b64, Limits::none()).map_err(|e| {
            anyhow::anyhow!("Failed to deserialize ContractCode LedgerEntry XDR: {}", e)
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
