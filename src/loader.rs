use anyhow::{bail, Context, Result};
use std::path::Path;
use stellar_xdr::curr::{
    ContractExecutable, LedgerEntry, LedgerEntryData, LedgerKey, LedgerKeyContractCode,
    LedgerKeyContractData, ScAddress, ScVal, Hash, Limits, ReadXdr, WriteXdr,
};
use wasmparser::{Parser, Payload};

/// Holds raw WASM bytes alongside the validated file path.
#[derive(Debug)]
pub struct WasmModule {
    pub path: String,
    pub bytes: Vec<u8>,
}

/// Reads a WASM file from disk, validates it is a valid WASM binary,
/// and returns a `WasmModule` ready for further analysis.
pub fn load_wasm(path: &Path) -> Result<WasmModule> {
    // 1. Check the file exists
    if !path.exists() {
        bail!("File not found: {}", path.display());
    }

    // 2. Read all bytes into memory
    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))?;

    // 3. Validate the WASM magic header (0x00 0x61 0x73 0x6d)
    if bytes.len() < 4 || &bytes[0..4] != b"\0asm" {
        bail!(
            "'{}' does not appear to be a valid WASM binary (bad magic bytes)",
            path.display()
        );
    }

    // 4. Do a full structural parse to detect any deeper format errors
    validate_wasm_structure(&bytes)
        .with_context(|| format!("WASM validation failed for '{}'", path.display()))?;

    Ok(WasmModule {
        path: path.to_string_lossy().into_owned(),
        bytes,
    })
}

/// Iterates through all WASM payloads and fails fast on any parse error.
fn validate_wasm_structure(bytes: &[u8]) -> Result<()> {
    let parser = Parser::new(0);
    for payload in parser.parse_all(bytes) {
        match payload.context("Malformed WASM payload encountered")? {
            // We just want to iterate; real analysis happens in later modules
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

/// Fetches a deployed Soroban contract's WASM bytes from Stellar RPC by contract ID.
pub fn fetch_wasm_from_rpc(contract_id: &str, rpc_url: &str) -> Result<WasmModule> {
    // 1. Parse contract_id using stellar_strkey
    let strkey = stellar_strkey::Strkey::from_string(contract_id)
        .map_err(|e| anyhow::anyhow!("Invalid contract ID '{}': {}", contract_id, e))?;

    let contract_bytes = match strkey {
        stellar_strkey::Strkey::Contract(c) => c.0,
        _ => bail!("Provided ID '{}' is not a valid contract ID", contract_id),
    };

    // 2. Build LedgerKey for contract instance
    let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(Hash(contract_bytes)),
        key: ScVal::LedgerKeyContractInstance,
        durability: stellar_xdr::curr::ContractDataDurability::Persistent,
    });

    // 3. Serialize LedgerKey to Base64
    let key_b64 = ledger_key
        .to_xdr_base64(Limits::none())
        .map_err(|e| anyhow::anyhow!("Failed to serialize LedgerKey to base64: {}", e))?;

    // 4. Query getLedgerEntries RPC
    let response = query_rpc(
        rpc_url,
        "getLedgerEntries",
        serde_json::json!({
            "keys": [key_b64]
        }),
    )?;

    // 5. Extract LedgerEntry XDR from response
    let entries = response["result"]["entries"]
        .as_array()
        .context("RPC response did not contain 'entries' array")?;

    if entries.is_empty() {
        bail!("Contract '{}' not found on-chain", contract_id);
    }

    let entry_xdr_b64 = entries[0]["xdr"]
        .as_str()
        .context("RPC response entry missing 'xdr' field")?;

    // 6. Deserialize LedgerEntry
    let entry = LedgerEntry::from_xdr_base64(entry_xdr_b64, Limits::none())
        .map_err(|e| anyhow::anyhow!("Failed to deserialize LedgerEntry XDR: {}", e))?;

    // 7. Get ContractInstance val
    let contract_data = match entry.data {
        LedgerEntryData::ContractData(cd) => cd,
        _ => bail!("Unexpected ledger entry type returned for contract instance"),
    };

    let instance = match contract_data.val {
        ScVal::ContractInstance(inst) => inst,
        _ => bail!("Expected ScVal::ContractInstance in contract data"),
    };

    // 8. Extract WASM hash from instance executable
    let wasm_hash = match instance.executable {
        ContractExecutable::Wasm(hash) => hash,
        ContractExecutable::StellarAsset => {
            bail!(
                "Contract '{}' is a built-in Stellar Asset contract and does not have WASM bytecode",
                contract_id
            );
        }
    };

    // 9. Fetch WASM code using WASM hash
    let code_ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: wasm_hash.clone(),
    });

    let code_key_b64 = code_ledger_key
        .to_xdr_base64(Limits::none())
        .map_err(|e| anyhow::anyhow!("Failed to serialize ContractCode LedgerKey to base64: {}", e))?;

    let code_response = query_rpc(
        rpc_url,
        "getLedgerEntries",
        serde_json::json!({
            "keys": [code_key_b64]
        }),
    )?;

    let code_entries = code_response["result"]["entries"]
        .as_array()
        .context("RPC response for contract code did not contain 'entries' array")?;

    if code_entries.is_empty() {
        bail!(
            "WASM code not found on-chain for hash {}",
            hex::encode(wasm_hash.0)
        );
    }

    let code_entry_xdr_b64 = code_entries[0]["xdr"]
        .as_str()
        .context("RPC response code entry missing 'xdr' field")?;

    let code_entry = LedgerEntry::from_xdr_base64(code_entry_xdr_b64, Limits::none())
        .map_err(|e| anyhow::anyhow!("Failed to deserialize ContractCode LedgerEntry XDR: {}", e))?;

    let contract_code = match code_entry.data {
        LedgerEntryData::ContractCode(code) => code,
        _ => bail!("Unexpected ledger entry type returned for contract code"),
    };

    let wasm_bytes = contract_code.code.to_vec();

    // Validate WASM bytes
    if wasm_bytes.len() < 4 || &wasm_bytes[0..4] != b"\0asm" {
        bail!(
            "Fetched WASM for contract '{}' has invalid magic bytes",
            contract_id
        );
    }

    validate_wasm_structure(&wasm_bytes)
        .with_context(|| format!("WASM validation failed for fetched contract '{}'", contract_id))?;

    Ok(WasmModule {
        path: format!("stellar://{}", contract_id),
        bytes: wasm_bytes,
    })
}

/// Helper to execute JSON-RPC request to Stellar RPC.
fn query_rpc(rpc_url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    });

    let response: serde_json::Value = ureq::post(rpc_url)
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

