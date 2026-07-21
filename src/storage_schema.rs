//! Storage-schema manifest: an opt-in declaration of what a contract actually
//! writes to storage.
//!
//! # Why this exists
//!
//! Soroban storage compatibility is decided by the bytes a contract writes to
//! persistent, instance, and temporary storage. Those bytes are governed by two
//! things: the contract's **storage-key** types, whose discriminants order and
//! address entries, and the layout of the **value types** it serializes into
//! storage. Neither has to appear in the exported `contractspecv0` section —
//! internal types used only as storage payloads are invisible to the spec.
//!
//! That means the exported interface can stay byte-identical across an upgrade
//! while the storage layout changes underneath it, which corrupts every existing
//! entry. A storage-schema manifest is the bridge: a team declares the types
//! that actually govern layout so they can be diffed with the same engine and
//! severities as exported types.
//!
//! # File format
//!
//! A manifest describes the storage layout of **one build**. To diff an upgrade
//! you supply the manifest for the old build and the one for the new build; a
//! single file cannot describe two layouts, and detecting a reorder inherently
//! requires both snapshots.
//!
//! ```toml
//! # Storage-key types: enums/unions whose discriminants address storage entries.
//! [[storage_key]]
//! name = "DataKey"
//! kind = "union"             # "union" (data-carrying) or "enum" (unit, integer-valued)
//! durability = "persistent"  # optional: persistent | instance | temporary
//!
//!   [[storage_key.variant]]
//!   name = "Admin"           # void variant — no payload
//!
//!   [[storage_key.variant]]
//!   name = "Position"
//!   type = ["Address"]       # tuple payload types
//!
//! # Internal value types serialized into storage.
//! [[value_type]]
//! name = "PositionState"
//! kind = "struct"
//! durability = "persistent"
//!
//!   [[value_type.field]]
//!   name = "collateral"
//!   type = "i128"
//!
//!   [[value_type.field]]
//!   name = "debt"
//!   type = "i128"
//! ```
//!
//! JSON is accepted with the same shape. Unknown keys are rejected rather than
//! ignored, so a typo fails loudly instead of silently narrowing coverage.
//!
//! ## Declaration order is layout
//!
//! Field order in a `struct` and variant order in a `union` are **significant**:
//! Soroban serializes them positionally, so the order you write them in is the
//! order stored on chain. Reordering or inserting is a breaking change and is
//! reported as such. For a unit `enum`, the explicit `value` is the discriminant.
//!
//! # Type language
//!
//! The `type` fields use the same Rust-like spelling that the report prints, so
//! declarations round-trip with [`crate::mapper::type_to_string`]:
//!
//! | Spelling | Meaning |
//! | --- | --- |
//! | `bool`, `u32`, `i32`, `u64`, `i64`, `u128`, `i128`, `u256`, `i256` | scalars |
//! | `Bytes`, `String`, `Symbol`, `Address`, `Timepoint`, `Duration` | built-ins |
//! | `Val`, `Error`, `()` | raw value, error, void |
//! | `Option<T>`, `Vec<T>`, `Map<K, V>`, `Result<T, E>` | containers |
//! | `BytesN<32>` | fixed-length bytes |
//! | `(A, B)` | tuple |
//! | `MyType` | a user-defined type, exported or declared in this manifest |

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use stellar_xdr::curr::{
    ScSpecTypeBytesN, ScSpecTypeDef, ScSpecTypeMap, ScSpecTypeOption, ScSpecTypeResult,
    ScSpecTypeTuple, ScSpecTypeUdt, ScSpecTypeVec, VecM,
};

/// The default manifest file name looked up alongside a build.
pub const DEFAULT_STORAGE_SCHEMA_FILE: &str = ".storage-schema.toml";

/// Maximum number of element types in a tuple, fixed by the XDR encoding.
const MAX_TUPLE_ARITY: usize = 12;

/// Which storage durability a declared type is written under.
///
/// Purely descriptive: it does not change how a type is diffed, but it is
/// surfaced in findings because the blast radius differs. A break in a
/// `persistent` type corrupts long-lived data, whereas a `temporary` type only
/// affects entries that would have expired anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Durability {
    Persistent,
    Instance,
    Temporary,
}

impl Durability {
    /// Lowercase label used in report messages.
    pub fn label(&self) -> &'static str {
        match self {
            Durability::Persistent => "persistent",
            Durability::Instance => "instance",
            Durability::Temporary => "temporary",
        }
    }
}

/// The shape of a declared type, mirroring the Soroban UDT kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeKind {
    /// Positionally serialized record of named fields.
    Struct,
    /// Unit enum with explicit integer discriminants.
    Enum,
    /// Data-carrying enum; cases are addressed by positional discriminant.
    Union,
}

impl TypeKind {
    pub fn label(&self) -> &'static str {
        match self {
            TypeKind::Struct => "struct",
            TypeKind::Enum => "enum",
            TypeKind::Union => "union",
        }
    }
}

/// Whether a declaration is a storage key or a stored value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclarationRole {
    /// A type used to build storage keys; its discriminants address entries.
    StorageKey,
    /// A type serialized as a stored value.
    ValueType,
}

impl DeclarationRole {
    pub fn label(&self) -> &'static str {
        match self {
            DeclarationRole::StorageKey => "storage key",
            DeclarationRole::ValueType => "storage value",
        }
    }
}

/// One field of a declared `struct`. Declaration order is layout order.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredField {
    pub name: String,
    /// The field type, in the spelling described in the module docs.
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default)]
    pub doc: Option<String>,
}

/// One case of a declared unit `enum`, with its explicit discriminant.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredCase {
    pub name: String,
    /// The integer discriminant actually written to storage.
    pub value: u32,
    #[serde(default)]
    pub doc: Option<String>,
}

/// One variant of a declared `union`. Declaration order is discriminant order.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredVariant {
    pub name: String,
    /// Tuple payload types. Omit (or leave empty) for a void variant.
    #[serde(default, rename = "type")]
    pub types: Vec<String>,
    #[serde(default)]
    pub doc: Option<String>,
}

/// A single declared type in a storage-schema manifest.
///
/// The `kind` selects which of `fields` / `cases` / `variants` is meaningful;
/// supplying the wrong one is a validation error rather than a silent no-op, so
/// a malformed manifest can never quietly reduce coverage.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredType {
    pub name: String,
    pub kind: TypeKind,
    #[serde(default)]
    pub doc: Option<String>,
    #[serde(default)]
    pub durability: Option<Durability>,
    /// Fields, for `kind = "struct"`.
    #[serde(default, rename = "field")]
    pub fields: Vec<DeclaredField>,
    /// Cases, for `kind = "enum"`.
    #[serde(default, rename = "case")]
    pub cases: Vec<DeclaredCase>,
    /// Variants, for `kind = "union"`.
    #[serde(default, rename = "variant")]
    pub variants: Vec<DeclaredVariant>,
}

impl DeclaredType {
    /// Human-readable durability label, defaulting to `persistent` — the
    /// conservative assumption, since it is the durability whose corruption is
    /// permanent.
    pub fn durability_label(&self) -> &'static str {
        self.durability
            .unwrap_or(Durability::Persistent)
            .label()
    }
}

/// A parsed storage-schema manifest describing one build's storage layout.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSchema {
    /// Types used to construct storage keys.
    #[serde(default, rename = "storage_key")]
    pub storage_keys: Vec<DeclaredType>,
    /// Types serialized as stored values.
    #[serde(default, rename = "value_type")]
    pub value_types: Vec<DeclaredType>,
}

impl StorageSchema {
    /// Every declaration paired with the role it was declared under.
    pub fn declarations(&self) -> impl Iterator<Item = (&DeclaredType, DeclarationRole)> {
        self.storage_keys
            .iter()
            .map(|t| (t, DeclarationRole::StorageKey))
            .chain(
                self.value_types
                    .iter()
                    .map(|t| (t, DeclarationRole::ValueType)),
            )
    }

    /// Total number of declared types across both roles.
    pub fn declared_count(&self) -> usize {
        self.storage_keys.len() + self.value_types.len()
    }

    /// Whether the manifest declares nothing at all.
    pub fn is_empty(&self) -> bool {
        self.declared_count() == 0
    }

    /// Look up a declaration by name, across both roles.
    pub fn find(&self, name: &str) -> Option<(&DeclaredType, DeclarationRole)> {
        self.declarations().find(|(t, _)| t.name == name)
    }
}

/// Parse a type string into the XDR type the diff engine compares.
///
/// The accepted spelling is the inverse of [`crate::mapper::type_to_string`], so
/// a type printed in a report can be pasted straight into a manifest.
pub fn parse_type_str(input: &str) -> Result<ScSpecTypeDef> {
    let s = input.trim();
    if s.is_empty() {
        bail!("expected a type name but found an empty string");
    }

    // Tuple (and the void spelling `()`).
    if s.starts_with('(') && s.ends_with(')') && is_fully_wrapped(s) {
        let parts = split_top_level(&s[1..s.len() - 1])
            .with_context(|| format!("Invalid tuple type `{s}`"))?;
        if parts.is_empty() {
            return Ok(ScSpecTypeDef::Void);
        }
        if parts.len() > MAX_TUPLE_ARITY {
            bail!(
                "Tuple type `{s}` has {} elements, but at most {MAX_TUPLE_ARITY} are encodable",
                parts.len()
            );
        }
        let types = parts
            .iter()
            .map(|p| parse_type_str(p))
            .collect::<Result<Vec<_>>>()?;
        return Ok(ScSpecTypeDef::Tuple(Box::new(ScSpecTypeTuple {
            value_types: VecM::try_from(types)
                .map_err(|e| anyhow::anyhow!("Invalid tuple type `{s}`: {e}"))?,
        })));
    }

    // Generic container: `Name<args>`.
    if let Some(open) = s.find('<') {
        if !s.ends_with('>') {
            bail!("Type `{s}` opens a generic parameter list with `<` but does not close it");
        }
        let name = s[..open].trim();
        let args = split_top_level(&s[open + 1..s.len() - 1])
            .with_context(|| format!("Invalid generic arguments in type `{s}`"))?;

        let expect = |n: usize| -> Result<()> {
            if args.len() != n {
                bail!(
                    "Type `{s}` expects {n} generic argument(s) but {} were given",
                    args.len()
                );
            }
            Ok(())
        };

        return match name {
            "Option" => {
                expect(1)?;
                Ok(ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
                    value_type: Box::new(parse_type_str(&args[0])?),
                })))
            }
            "Vec" => {
                expect(1)?;
                Ok(ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
                    element_type: Box::new(parse_type_str(&args[0])?),
                })))
            }
            "Map" => {
                expect(2)?;
                Ok(ScSpecTypeDef::Map(Box::new(ScSpecTypeMap {
                    key_type: Box::new(parse_type_str(&args[0])?),
                    value_type: Box::new(parse_type_str(&args[1])?),
                })))
            }
            "Result" => {
                expect(2)?;
                Ok(ScSpecTypeDef::Result(Box::new(ScSpecTypeResult {
                    ok_type: Box::new(parse_type_str(&args[0])?),
                    error_type: Box::new(parse_type_str(&args[1])?),
                })))
            }
            "BytesN" => {
                expect(1)?;
                let n: u32 = args[0].trim().parse().with_context(|| {
                    format!("BytesN length must be a number, got `{}`", args[0])
                })?;
                Ok(ScSpecTypeDef::BytesN(ScSpecTypeBytesN { n }))
            }
            other => bail!(
                "Unknown generic type `{other}` in `{s}`. \
                 Supported: Option, Vec, Map, Result, BytesN"
            ),
        };
    }

    // Scalars, built-ins, and user-defined type references.
    Ok(match s {
        "Val" => ScSpecTypeDef::Val,
        "bool" => ScSpecTypeDef::Bool,
        "void" | "()" => ScSpecTypeDef::Void,
        "Error" => ScSpecTypeDef::Error,
        "u32" => ScSpecTypeDef::U32,
        "i32" => ScSpecTypeDef::I32,
        "u64" => ScSpecTypeDef::U64,
        "i64" => ScSpecTypeDef::I64,
        "Timepoint" => ScSpecTypeDef::Timepoint,
        "Duration" => ScSpecTypeDef::Duration,
        "u128" => ScSpecTypeDef::U128,
        "i128" => ScSpecTypeDef::I128,
        "u256" => ScSpecTypeDef::U256,
        "i256" => ScSpecTypeDef::I256,
        "Bytes" => ScSpecTypeDef::Bytes,
        "String" => ScSpecTypeDef::String,
        "Symbol" => ScSpecTypeDef::Symbol,
        "Address" => ScSpecTypeDef::Address,
        udt => {
            if !is_valid_type_name(udt) {
                bail!(
                    "`{udt}` is not a valid type name. Expected a scalar, a container \
                     (Option/Vec/Map/Result/BytesN), a tuple, or a user-defined type name"
                );
            }
            ScSpecTypeDef::Udt(ScSpecTypeUdt {
                name: udt.try_into().map_err(|_| {
                    anyhow::anyhow!("User-defined type name `{udt}` exceeds the 60-character limit")
                })?,
            })
        }
    })
}

/// Whether a bare identifier is plausibly a user-defined type name.
fn is_valid_type_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether the whole string is wrapped by its leading bracket, i.e. the bracket
/// opened at index 0 is the one closed at the final character.
fn is_fully_wrapped(s: &str) -> bool {
    let mut depth = 0i32;
    let chars: Vec<char> = s.chars().collect();
    for (i, ch) in chars.iter().enumerate() {
        match ch {
            '(' | '<' => depth += 1,
            ')' | '>' => depth -= 1,
            _ => {}
        }
        if depth == 0 && i + 1 != chars.len() {
            return false;
        }
        if depth < 0 {
            return false;
        }
    }
    depth == 0
}

/// Split on commas that sit at bracket depth zero.
fn split_top_level(input: &str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;

    for ch in input.chars() {
        match ch {
            '<' | '(' => {
                depth += 1;
                current.push(ch);
            }
            '>' | ')' => {
                depth -= 1;
                if depth < 0 {
                    bail!("unbalanced brackets in `{input}`");
                }
                current.push(ch);
            }
            ',' if depth == 0 => {
                let part = current.trim();
                if part.is_empty() {
                    bail!("empty element in `{input}`");
                }
                parts.push(part.to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if depth != 0 {
        bail!("unbalanced brackets in `{input}`");
    }

    let last = current.trim();
    if last.is_empty() {
        if !parts.is_empty() {
            bail!("trailing comma in `{input}`");
        }
    } else {
        parts.push(last.to_string());
    }

    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapper::type_to_string;

    /// Every spelling the manifest accepts must round-trip through the same
    /// renderer the report uses, so a type printed in a finding can be pasted
    /// straight back into a manifest.
    #[test]
    fn type_spellings_round_trip_through_the_report_renderer() {
        for spelling in [
            "bool",
            "u32",
            "i128",
            "u256",
            "Address",
            "Symbol",
            "Bytes",
            "Timepoint",
            "Option<u32>",
            "Vec<Address>",
            "Map<Symbol, i128>",
            "Result<u32, Error>",
            "BytesN<32>",
            "(Address, u32)",
            "Vec<Map<Symbol, Vec<u32>>>",
            "PositionState",
        ] {
            let parsed = parse_type_str(spelling)
                .unwrap_or_else(|e| panic!("`{spelling}` should parse: {e}"));
            assert_eq!(
                type_to_string(&parsed),
                spelling,
                "`{spelling}` did not round-trip"
            );
        }
    }

    #[test]
    fn empty_tuple_is_void() {
        assert_eq!(parse_type_str("()").unwrap(), ScSpecTypeDef::Void);
        assert_eq!(parse_type_str("void").unwrap(), ScSpecTypeDef::Void);
    }

    #[test]
    fn udt_names_are_parsed_as_user_defined_types() {
        let parsed = parse_type_str("DataKey").unwrap();
        match parsed {
            ScSpecTypeDef::Udt(udt) => assert_eq!(udt.name.to_string(), "DataKey"),
            other => panic!("expected a Udt, got {other:?}"),
        }
    }

    #[test]
    fn nested_generics_split_on_the_right_commas() {
        // The inner comma belongs to the Map, not to the outer argument list.
        let parsed = parse_type_str("Map<Symbol, Map<u32, Address>>").unwrap();
        assert_eq!(type_to_string(&parsed), "Map<Symbol, Map<u32, Address>>");
    }

    #[test]
    fn malformed_type_strings_fail_loudly() {
        for bad in [
            "",
            "Vec<",
            "Vec<u32",
            "Map<u32>",             // wrong arity
            "Option<u32, u32>",     // wrong arity
            "Unknown<u32>",         // unsupported container
            "BytesN<abc>",          // non-numeric length
            "(u32,)",               // trailing comma
            "123Bad",               // not an identifier
        ] {
            assert!(
                parse_type_str(bad).is_err(),
                "`{bad}` should have been rejected"
            );
        }
    }

    #[test]
    fn manifest_parses_keys_and_value_types() {
        let schema: StorageSchema = toml::from_str(
            r#"
            [[storage_key]]
            name = "DataKey"
            kind = "union"
            durability = "persistent"

              [[storage_key.variant]]
              name = "Admin"

              [[storage_key.variant]]
              name = "Position"
              type = ["Address"]

            [[value_type]]
            name = "PositionState"
            kind = "struct"

              [[value_type.field]]
              name = "collateral"
              type = "i128"

              [[value_type.field]]
              name = "debt"
              type = "i128"
            "#,
        )
        .expect("manifest should parse");

        assert_eq!(schema.declared_count(), 2);

        let (key, role) = schema.find("DataKey").expect("DataKey should be declared");
        assert_eq!(role, DeclarationRole::StorageKey);
        assert_eq!(key.kind, TypeKind::Union);
        assert_eq!(key.durability, Some(Durability::Persistent));
        assert_eq!(key.variants.len(), 2);
        // Declaration order is discriminant order.
        assert_eq!(key.variants[0].name, "Admin");
        assert!(key.variants[0].types.is_empty(), "Admin is a void variant");
        assert_eq!(key.variants[1].types, vec!["Address".to_string()]);

        let (value, role) = schema.find("PositionState").expect("declared");
        assert_eq!(role, DeclarationRole::ValueType);
        assert_eq!(value.kind, TypeKind::Struct);
        // Unspecified durability reads as persistent — the conservative default.
        assert_eq!(value.durability_label(), "persistent");
        let field_names: Vec<&str> = value.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(field_names, vec!["collateral", "debt"]);
    }

    #[test]
    fn manifest_accepts_the_same_shape_as_json() {
        let schema: StorageSchema = serde_json::from_str(
            r#"{
                "value_type": [
                    {
                        "name": "Config",
                        "kind": "enum",
                        "case": [
                            { "name": "Paused", "value": 0 },
                            { "name": "Active", "value": 1 }
                        ]
                    }
                ]
            }"#,
        )
        .expect("JSON manifest should parse");

        let (config, _) = schema.find("Config").expect("Config should be declared");
        assert_eq!(config.kind, TypeKind::Enum);
        assert_eq!(config.cases.len(), 2);
        assert_eq!(config.cases[1].value, 1);
    }

    /// A typo must not silently narrow coverage: unknown keys are rejected.
    #[test]
    fn unknown_manifest_keys_are_rejected() {
        let result: Result<StorageSchema, _> = toml::from_str(
            r#"
            [[value_type]]
            name = "Thing"
            kind = "struct"
            fields = []          # wrong key: the table is [[value_type.field]]
            "#,
        );
        assert!(result.is_err(), "unknown keys must fail loudly");
    }

    /// The shipped example is documentation users will copy, so it must parse
    /// and every type spelling in it must resolve.
    #[test]
    fn the_shipped_example_manifest_is_valid() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".storage-schema.example.toml");
        let contents = std::fs::read_to_string(&path).expect("example manifest must exist");
        let schema: StorageSchema =
            toml::from_str(&contents).expect("example manifest must parse");

        assert!(!schema.is_empty(), "example should declare types");
        for (declared, _role) in schema.declarations() {
            for field in &declared.fields {
                parse_type_str(&field.type_).unwrap_or_else(|e| {
                    panic!("{}.{}: {e}", declared.name, field.name)
                });
            }
            for variant in &declared.variants {
                for type_ in &variant.types {
                    parse_type_str(type_).unwrap_or_else(|e| {
                        panic!("{}::{}: {e}", declared.name, variant.name)
                    });
                }
            }
        }
    }

    #[test]
    fn an_absent_manifest_section_is_simply_empty() {
        let schema: StorageSchema = toml::from_str("").expect("empty manifest is valid");
        assert!(schema.is_empty());
        assert_eq!(schema.declarations().count(), 0);
    }
}
