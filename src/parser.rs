use anyhow::{Context, Result};
use std::io::Cursor;
use stellar_xdr::curr::{Limited, Limits, ReadXdr, ScEnvMetaEntry, ScSpecEntry};
use wasmparser::{Parser, Payload};

/// Decoded contents of a contract's `contractenvmetav0` custom section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractEnvMeta {
    pub entries: Vec<ScEnvMetaEntry>,
}

impl ContractEnvMeta {
    /// The packed Soroban interface version, when present.
    pub fn interface_version(&self) -> Option<u64> {
        self.entries.iter().find_map(|entry| match entry {
            ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(version) => Some(*version),
        })
    }

    /// Ledger / protocol version (high 32 bits of the interface version).
    pub fn protocol_version(&self) -> Option<u32> {
        self.interface_version().map(|v| (v >> 32) as u32)
    }

    /// Pre-release component of the interface version (low 32 bits).
    pub fn pre_release_version(&self) -> Option<u32> {
        self.interface_version().map(|v| v as u32)
    }

    /// Short human-readable summary for report messages.
    pub fn summary(&self) -> String {
        if let Some(version) = self.interface_version() {
            format!(
                "protocol {}, pre-release {}",
                version >> 32,
                version as u32
            )
        } else if self.entries.is_empty() {
            "empty".to_string()
        } else {
            format!("{} environment metadata entries", self.entries.len())
        }
    }
}

/// Represents the extracted Soroban-specific custom sections from a WASM module.
#[derive(Debug, Default)]
pub struct SorobanMetadata {
    pub spec: Vec<ScSpecEntry>,
    pub env_meta: Option<ContractEnvMeta>,
}

/// Decodes concatenated ScSpecEntry XDR objects from raw bytes.
///
/// Soroban custom sections contain multiple XDR-encoded entries back to back.
/// We wrap the data in a `Limited<Cursor>` and call `read_xdr` in a loop,
/// checking the cursor position to detect when all bytes are consumed.
fn decode_spec_entries(data: &[u8]) -> Result<Vec<ScSpecEntry>> {
    let cursor = Cursor::new(data);
    let mut limited = Limited::new(cursor, Limits::none());
    let mut entries = Vec::new();

    while (limited.inner.position() as usize) < data.len() {
        let entry_index = entries.len();
        let byte_offset = limited.inner.position();
        let entry = ScSpecEntry::read_xdr(&mut limited).with_context(|| {
            format!(
                "Failed to decode ScSpecEntry XDR at entry index {} (byte offset {})",
                entry_index, byte_offset
            )
        })?;
        entries.push(entry);
    }

    Ok(entries)
}

/// Decodes concatenated ScEnvMetaEntry XDR objects from raw bytes.
fn decode_env_meta_entries(data: &[u8]) -> Result<Vec<ScEnvMetaEntry>> {
    let cursor = Cursor::new(data);
    let mut limited = Limited::new(cursor, Limits::none());
    let mut entries = Vec::new();

    while (limited.inner.position() as usize) < data.len() {
        let entry =
            ScEnvMetaEntry::read_xdr(&mut limited).context("Failed to decode ScEnvMetaEntry XDR")?;
        entries.push(entry);
    }

    Ok(entries)
}

/// Decodes a `contractenvmetav0` section into a comparable representation.
pub fn decode_env_meta(data: &[u8]) -> Result<ContractEnvMeta> {
    let entries = decode_env_meta_entries(data)?;
    Ok(ContractEnvMeta { entries })
}

/// Parses the WASM bytes to extract Soroban-specific custom sections and decodes them.
pub fn extract_metadata(bytes: &[u8]) -> Result<SorobanMetadata> {
    let mut metadata = SorobanMetadata::default();
    let parser = Parser::new(0);

    let mut spec_section_index = 0usize;

    for payload in parser.parse_all(bytes) {
        if let Payload::CustomSection(section) = payload.context("Failed to parse WASM payload")? {
            match section.name() {
                "contractspecv0" => {
                    let section_index = spec_section_index;
                    spec_section_index += 1;

                    let entries = decode_spec_entries(section.data()).with_context(|| {
                        format!(
                            "Failed to decode contractspecv0 section {} at byte offset {}",
                            section_index,
                            section.data_offset()
                        )
                    })?;
                    metadata.spec.extend(entries);
                }
                "contractenvmetav0" => {
                    metadata.env_meta = decode_env_meta(section.data()).ok();
                }
                _ => {}
            }
        }
    }

    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use stellar_xdr::curr::{ScEnvMetaEntry, WriteXdr};

    fn encode_interface_version(protocol: u32, pre_release: u32) -> Vec<u8> {
        let version = ((protocol as u64) << 32) | (pre_release as u64);
        let entry = ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(version);
        let cursor = Cursor::new(Vec::new());
        let mut limited = Limited::new(cursor, Limits::none());
        entry.write_xdr(&mut limited).unwrap();
        limited.inner.into_inner()
    }

    fn fixture_contractspec_bytes() -> Vec<u8> {
        let wasm = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/wasm/v1.wasm"),
        )
        .expect("v1.wasm fixture must exist");

        for payload in Parser::new(0).parse_all(&wasm) {
            if let Payload::CustomSection(section) = payload.expect("valid wasm payload") {
                if section.name() == "contractspecv0" {
                    return section.data().to_vec();
                }
            }
        }

        panic!("v1.wasm fixture must contain a contractspecv0 section");
    }

    fn wasm_with_custom_section(name: &str, data: &[u8]) -> Vec<u8> {
        let section_size = 1 + name.len() + data.len();
        assert!(section_size < 128, "test helper only encodes small sections");

        let mut wasm = Vec::from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
        wasm.push(0);
        wasm.push(section_size as u8);
        wasm.push(name.len() as u8);
        wasm.extend_from_slice(name.as_bytes());
        wasm.extend_from_slice(data);
        wasm
    }

    #[test]
    fn decode_env_meta_reads_interface_version() {
        let bytes = encode_interface_version(21, 0);
        let meta = decode_env_meta(&bytes).unwrap();

        assert_eq!(meta.protocol_version(), Some(21));
        assert_eq!(meta.pre_release_version(), Some(0));
        assert_eq!(meta.interface_version(), Some(21 << 32));
    }

    #[test]
    fn decode_env_meta_rejects_truncated_bytes() {
        let bytes = encode_interface_version(21, 0);
        assert!(decode_env_meta(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn decode_spec_entries_reports_entry_index_and_offset_for_truncated_bytes() {
        let bytes = fixture_contractspec_bytes();
        let decoded_entries = decode_spec_entries(&bytes).expect("fixture spec must decode");
        assert!(
            decoded_entries.len() > 1,
            "fixture should contain enough entries to verify the failing index"
        );

        let error =
            decode_spec_entries(&bytes[..bytes.len() - 1]).expect_err("truncated spec must fail");
        let message = error.to_string();

        assert!(
            message.contains(&format!("entry index {}", decoded_entries.len() - 1)),
            "error should name the failing entry index, got: {message}"
        );
        assert!(
            message.contains("byte offset"),
            "error should name the failing byte offset, got: {message}"
        );
    }

    #[test]
    fn extract_metadata_reports_contractspec_section_offset_for_decode_errors() {
        let wasm = wasm_with_custom_section("contractspecv0", &[0x00]);
        let error = extract_metadata(&wasm).expect_err("invalid spec section must fail");
        let messages = error
            .chain()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        assert!(
            messages.iter().any(|message| {
                message.contains("contractspecv0 section 0")
                    && message.contains("byte offset")
            }),
            "error chain should name the contractspecv0 section offset, got: {messages:?}"
        );
        assert!(
            messages.iter().any(|message| {
                message.contains("ScSpecEntry XDR") && message.contains("entry index 0")
            }),
            "error chain should include the failing spec entry index, got: {messages:?}"
        );
    }

    #[test]
    fn extract_metadata_skips_invalid_env_meta_without_error() {
        let wasm = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/wasm/v1.wasm"),
        )
        .expect("v1.wasm fixture must exist");

        let metadata = extract_metadata(&wasm).expect("valid wasm must parse");
        assert!(
            metadata.env_meta.is_some(),
            "fixture wasm should contain decodable env metadata"
        );
    }
}
