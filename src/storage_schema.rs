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

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use stellar_xdr::curr::{
    ScSpecTypeBytesN, ScSpecTypeDef, ScSpecTypeMap, ScSpecTypeOption, ScSpecTypeResult,
    ScSpecTypeTuple, ScSpecTypeUdt, ScSpecTypeVec, ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0,
    ScSpecUdtStructFieldV0, ScSpecUdtStructV0, ScSpecUdtUnionCaseTupleV0, ScSpecUdtUnionCaseV0,
    ScSpecUdtUnionCaseVoidV0, ScSpecUdtUnionV0, StringM, VecM,
};

use crate::mapper::type_to_string;
use crate::spec::ContractSpec;

/// The default manifest file name looked up alongside a build.
pub const DEFAULT_STORAGE_SCHEMA_FILE: &str = ".storage-schema.toml";

/// Maximum number of element types in a tuple, fixed by the XDR encoding.
const MAX_TUPLE_ARITY: usize = 12;

/// Upper bound on declared types in one manifest.
///
/// A schema this large is far past anything a real contract needs and is more
/// likely a generated or malformed file; refusing it keeps analysis bounded.
const MAX_DECLARED_TYPES: usize = 2_000;

/// Upper bound on members (fields/cases/variants) within a single declaration.
const MAX_MEMBERS_PER_TYPE: usize = 500;

/// XDR length limit for a struct field name.
const MAX_FIELD_NAME_LEN: usize = 30;

/// XDR length limit for a type, case, or variant name.
const MAX_TYPE_NAME_LEN: usize = 60;

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

    /// Parse a manifest from a TOML string, without validating it.
    pub fn from_toml_str(contents: &str) -> Result<Self> {
        toml::from_str(contents).context("Failed to parse storage schema as TOML")
    }

    /// Parse a manifest from a JSON string, without validating it.
    pub fn from_json_str(contents: &str) -> Result<Self> {
        serde_json::from_str(contents).context("Failed to parse storage schema as JSON")
    }

    /// Parse a manifest in whichever of TOML or JSON it is written in.
    ///
    /// The file extension picks the format to try first; the other is attempted
    /// as a fallback so a `.txt` or extensionless manifest still works. If both
    /// fail, the error from the *expected* format is surfaced, because that is
    /// the one whose message will actually help.
    pub fn from_str_auto(contents: &str, path: &Path) -> Result<Self> {
        let looks_like_json = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("json"));

        if looks_like_json {
            Self::from_json_str(contents).or_else(|primary| Self::from_toml_str(contents).map_err(|_| primary))
        } else {
            Self::from_toml_str(contents).or_else(|primary| Self::from_json_str(contents).map_err(|_| primary))
        }
    }

    /// Load and validate a manifest from disk.
    ///
    /// Validation runs here rather than being left to the caller: a manifest is
    /// a safety input, and one that is silently half-understood would narrow
    /// coverage while still looking like it widened it.
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read storage schema '{}'", path.display()))?;
        let schema = Self::from_str_auto(&contents, path)
            .with_context(|| format!("Invalid storage schema '{}'", path.display()))?;
        schema
            .validate()
            .with_context(|| format!("Invalid storage schema '{}'", path.display()))?;
        Ok(schema)
    }

    /// Load a manifest if the file exists, returning `None` when it is absent.
    /// A present-but-malformed file is still an error, so a typo never silently
    /// disables storage analysis.
    pub fn load_optional(path: &Path) -> Result<Option<Self>> {
        if path.exists() {
            Ok(Some(Self::load_from_path(path)?))
        } else {
            Ok(None)
        }
    }

    /// Check the manifest is internally consistent and encodable.
    ///
    /// Every failure here is a hard error. A storage schema exists to make the
    /// verdict *more* trustworthy, so a manifest we only partly understand must
    /// never be accepted as if it were fully understood.
    pub fn validate(&self) -> Result<()> {
        if self.declared_count() > MAX_DECLARED_TYPES {
            bail!(
                "Storage schema declares {} types, exceeding the supported maximum of {}",
                self.declared_count(),
                MAX_DECLARED_TYPES
            );
        }

        let mut seen: HashMap<&str, DeclarationRole> = HashMap::new();
        for (declared, role) in self.declarations() {
            if let Some(previous) = seen.insert(declared.name.as_str(), role) {
                bail!(
                    "Storage schema declares type '{}' more than once (as a {} and again as a {}). \
                     Declare each type exactly once; a type cannot have two layouts.",
                    declared.name,
                    previous.label(),
                    role.label()
                );
            }
            validate_declared_type(declared, role)?;
        }

        Ok(())
    }

    /// Fail if any declaration contradicts the exported spec of the same build.
    ///
    /// A type may legitimately be absent from the exported spec — that is the
    /// whole point of the manifest. But when a name *is* exported, the manifest
    /// must agree with it. A manifest that contradicts the spec is worse than no
    /// manifest at all: it would silently certify a layout the contract does not
    /// actually use, so disagreement is a hard error rather than a warning.
    ///
    /// `build_label` names the side being checked ("old" / "new") so the message
    /// points at the right file.
    pub fn reconcile_with_spec(&self, spec: &ContractSpec, build_label: &str) -> Result<()> {
        for (declared, _role) in self.declarations() {
            reconcile_declared_type(declared, spec, build_label).with_context(|| {
                format!(
                    "Storage schema for the {build_label} build disagrees with that build's \
                     exported contract spec"
                )
            })?;
        }
        Ok(())
    }

    /// Turn the manifest into the `ScSpecUdt`-shaped model the diff engine reads.
    ///
    /// This is the bridge that lets storage types — including ones the exported
    /// spec never mentions — flow through exactly the same comparison and
    /// severity logic as exported types. Each declaration becomes the same XDR
    /// struct/enum/union the Soroban SDK would emit, so the resolved
    /// [`ContractSpec`] is indistinguishable to the diff engine from one decoded
    /// out of a WASM section.
    ///
    /// Types referenced by a declaration but not themselves declared are left as
    /// opaque `Udt` references; that is correct for diffing the declaring type,
    /// and [`StorageSchema::unresolved_references`] reports any that resolve to
    /// nothing so the gap is visible rather than silent.
    pub fn resolve(&self) -> Result<ResolvedStorageSchema> {
        let mut spec = ContractSpec::default();
        let mut meta: HashMap<String, ResolvedTypeMeta> = HashMap::new();

        for (declared, role) in self.declarations() {
            let durability = declared.durability.unwrap_or(Durability::Persistent);
            meta.insert(
                declared.name.clone(),
                ResolvedTypeMeta { role, durability },
            );

            match declared.kind {
                TypeKind::Struct => {
                    spec.structs
                        .insert(declared.name.clone(), resolve_struct(declared)?);
                }
                TypeKind::Enum => {
                    spec.enums
                        .insert(declared.name.clone(), resolve_enum(declared)?);
                }
                TypeKind::Union => {
                    spec.unions
                        .insert(declared.name.clone(), resolve_union(declared)?);
                }
            }
        }

        Ok(ResolvedStorageSchema { spec, meta })
    }

    /// UDT names a declaration refers to that resolve to nothing.
    ///
    /// A reference resolves if the name is declared in this manifest or, when an
    /// exported spec is supplied, exported by the build. Anything left over is a
    /// dangling reference — its layout is unknown, so a diff of the referring
    /// type cannot fully reason about it. Returning these lets the caller state
    /// the limitation instead of quietly analyzing an incomplete graph.
    pub fn unresolved_references(&self, exported: Option<&ContractSpec>) -> Vec<String> {
        let declared: HashSet<&str> = self.declarations().map(|(t, _)| t.name.as_str()).collect();
        let mut unresolved: BTreeSet<String> = BTreeSet::new();

        for (referring, _role) in self.declarations() {
            let mut referenced = HashSet::new();
            collect_declaration_references(referring, &mut referenced);
            for name in referenced {
                if declared.contains(name.as_str()) {
                    continue;
                }
                if exported.is_some_and(|spec| exported_kind_of(&name, spec).is_some()) {
                    continue;
                }
                unresolved.insert(name);
            }
        }

        unresolved.into_iter().collect()
    }
}

/// The resolved, diff-ready form of a storage schema.
#[derive(Debug, Clone, Default)]
pub struct ResolvedStorageSchema {
    /// The declared types as a [`ContractSpec`] the diff engine compares.
    pub spec: ContractSpec,
    /// Role and durability metadata for each declared type, keyed by name.
    pub meta: HashMap<String, ResolvedTypeMeta>,
}

impl ResolvedStorageSchema {
    /// Number of declared storage-key types.
    pub fn key_type_count(&self) -> usize {
        self.meta
            .values()
            .filter(|m| m.role == DeclarationRole::StorageKey)
            .count()
    }

    /// Number of declared storage value types.
    pub fn value_type_count(&self) -> usize {
        self.meta
            .values()
            .filter(|m| m.role == DeclarationRole::ValueType)
            .count()
    }
}

/// Role and durability carried alongside a resolved type, for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedTypeMeta {
    pub role: DeclarationRole,
    pub durability: Durability,
}

fn doc_string(doc: &Option<String>) -> Result<StringM<1024>> {
    doc.as_deref()
        .unwrap_or("")
        .try_into()
        .map_err(|_| anyhow::anyhow!("doc string exceeds the 1024-character limit"))
}

fn resolve_struct(declared: &DeclaredType) -> Result<ScSpecUdtStructV0> {
    let fields = declared
        .fields
        .iter()
        .map(|field| {
            Ok(ScSpecUdtStructFieldV0 {
                doc: doc_string(&field.doc)?,
                name: field.name.as_str().try_into().map_err(|_| {
                    anyhow::anyhow!("field name '{}' exceeds the length limit", field.name)
                })?,
                type_: parse_type_str(&field.type_)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ScSpecUdtStructV0 {
        doc: doc_string(&declared.doc)?,
        lib: StringM::default(),
        name: declared.name.as_str().try_into().map_err(|_| {
            anyhow::anyhow!("type name '{}' exceeds the length limit", declared.name)
        })?,
        fields: VecM::try_from(fields)
            .map_err(|e| anyhow::anyhow!("struct '{}': {e}", declared.name))?,
    })
}

fn resolve_enum(declared: &DeclaredType) -> Result<ScSpecUdtEnumV0> {
    let cases = declared
        .cases
        .iter()
        .map(|case| {
            Ok(ScSpecUdtEnumCaseV0 {
                doc: doc_string(&case.doc)?,
                name: case.name.as_str().try_into().map_err(|_| {
                    anyhow::anyhow!("case name '{}' exceeds the length limit", case.name)
                })?,
                value: case.value,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ScSpecUdtEnumV0 {
        doc: doc_string(&declared.doc)?,
        lib: StringM::default(),
        name: declared.name.as_str().try_into().map_err(|_| {
            anyhow::anyhow!("type name '{}' exceeds the length limit", declared.name)
        })?,
        cases: VecM::try_from(cases)
            .map_err(|e| anyhow::anyhow!("enum '{}': {e}", declared.name))?,
    })
}

fn resolve_union(declared: &DeclaredType) -> Result<ScSpecUdtUnionV0> {
    let cases = declared
        .variants
        .iter()
        .map(|variant| {
            let doc = doc_string(&variant.doc)?;
            let name: StringM<60> = variant.name.as_str().try_into().map_err(|_| {
                anyhow::anyhow!("variant name '{}' exceeds the length limit", variant.name)
            })?;

            if variant.types.is_empty() {
                Ok(ScSpecUdtUnionCaseV0::VoidV0(ScSpecUdtUnionCaseVoidV0 {
                    doc,
                    name,
                }))
            } else {
                let types = variant
                    .types
                    .iter()
                    .map(|t| parse_type_str(t))
                    .collect::<Result<Vec<_>>>()?;
                Ok(ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
                    doc,
                    name,
                    type_: VecM::try_from(types)
                        .map_err(|e| anyhow::anyhow!("variant '{}': {e}", variant.name))?,
                }))
            }
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ScSpecUdtUnionV0 {
        doc: doc_string(&declared.doc)?,
        lib: StringM::default(),
        name: declared.name.as_str().try_into().map_err(|_| {
            anyhow::anyhow!("type name '{}' exceeds the length limit", declared.name)
        })?,
        cases: VecM::try_from(cases)
            .map_err(|e| anyhow::anyhow!("union '{}': {e}", declared.name))?,
    })
}

/// Collect the UDT names a declaration references across all its members.
///
/// Type strings that fail to parse are skipped here rather than raised:
/// resolution is only ever called after [`StorageSchema::validate`], which has
/// already rejected unparseable types, so this stays a pure name walk.
fn collect_declaration_references(declared: &DeclaredType, out: &mut HashSet<String>) {
    let mut visit = |spelling: &str| {
        if let Ok(type_def) = parse_type_str(spelling) {
            collect_udt_names(&type_def, out);
        }
    };
    for field in &declared.fields {
        visit(&field.type_);
    }
    for variant in &declared.variants {
        for type_ in &variant.types {
            visit(type_);
        }
    }
    // Unit enums carry no payload types, so they reference nothing.
}

/// Recursively collect UDT names appearing anywhere inside a type.
fn collect_udt_names(type_def: &ScSpecTypeDef, out: &mut HashSet<String>) {
    match type_def {
        ScSpecTypeDef::Option(opt) => collect_udt_names(&opt.value_type, out),
        ScSpecTypeDef::Result(res) => {
            collect_udt_names(&res.ok_type, out);
            collect_udt_names(&res.error_type, out);
        }
        ScSpecTypeDef::Vec(vec) => collect_udt_names(&vec.element_type, out),
        ScSpecTypeDef::Map(map) => {
            collect_udt_names(&map.key_type, out);
            collect_udt_names(&map.value_type, out);
        }
        ScSpecTypeDef::Tuple(tuple) => {
            for t in tuple.value_types.iter() {
                collect_udt_names(t, out);
            }
        }
        ScSpecTypeDef::Udt(udt) => {
            out.insert(udt.name.to_string());
        }
        _ => {}
    }
}

/// Validate one declaration's shape, names, and type strings.
fn validate_declared_type(declared: &DeclaredType, role: DeclarationRole) -> Result<()> {
    let name = &declared.name;
    let context = format!("{} '{}'", role.label(), name);

    if !is_valid_type_name(name) {
        bail!("Storage schema declares an invalid type name '{name}' ({context})");
    }
    if name.len() > MAX_TYPE_NAME_LEN {
        bail!(
            "Type name '{name}' is {} characters, exceeding the {MAX_TYPE_NAME_LEN}-character limit",
            name.len()
        );
    }

    // The `kind` selects exactly one member table. Supplying another is a
    // mistake that would otherwise silently drop part of the declared layout.
    let wrong = match declared.kind {
        TypeKind::Struct => [
            ("case", declared.cases.is_empty()),
            ("variant", declared.variants.is_empty()),
        ],
        TypeKind::Enum => [
            ("field", declared.fields.is_empty()),
            ("variant", declared.variants.is_empty()),
        ],
        TypeKind::Union => [
            ("field", declared.fields.is_empty()),
            ("case", declared.cases.is_empty()),
        ],
    };
    for (table, empty) in wrong {
        if !empty {
            bail!(
                "{context} declares kind = \"{}\" but also supplies [[{table}]] entries. \
                 A {} uses [[{}]] entries.",
                declared.kind.label(),
                declared.kind.label(),
                expected_member_table(declared.kind)
            );
        }
    }

    match declared.kind {
        TypeKind::Struct => {
            check_member_count(declared.fields.len(), &context)?;
            let mut seen = Vec::new();
            for (index, field) in declared.fields.iter().enumerate() {
                if field.name.is_empty() {
                    bail!("{context}: field at position {index} has an empty name");
                }
                if field.name.len() > MAX_FIELD_NAME_LEN {
                    bail!(
                        "{context}: field name '{}' is {} characters, exceeding the \
                         {MAX_FIELD_NAME_LEN}-character limit",
                        field.name,
                        field.name.len()
                    );
                }
                if seen.contains(&field.name.as_str()) {
                    bail!("{context}: duplicate field '{}'", field.name);
                }
                seen.push(field.name.as_str());
                parse_type_str(&field.type_)
                    .with_context(|| format!("{context}: field '{}'", field.name))?;
            }
        }
        TypeKind::Enum => {
            if declared.cases.is_empty() {
                bail!("{context}: an enum must declare at least one [[case]]");
            }
            check_member_count(declared.cases.len(), &context)?;
            let mut seen_names = Vec::new();
            let mut seen_values = Vec::new();
            for case in &declared.cases {
                check_case_name(&case.name, &context)?;
                if seen_names.contains(&case.name.as_str()) {
                    bail!("{context}: duplicate case '{}'", case.name);
                }
                // Two cases sharing a discriminant is unrepresentable on chain.
                if seen_values.contains(&case.value) {
                    bail!(
                        "{context}: case '{}' reuses discriminant {}. \
                         Each case must have a distinct value.",
                        case.name,
                        case.value
                    );
                }
                seen_names.push(case.name.as_str());
                seen_values.push(case.value);
            }
        }
        TypeKind::Union => {
            if declared.variants.is_empty() {
                bail!("{context}: a union must declare at least one [[variant]]");
            }
            check_member_count(declared.variants.len(), &context)?;
            let mut seen = Vec::new();
            for variant in &declared.variants {
                check_case_name(&variant.name, &context)?;
                if seen.contains(&variant.name.as_str()) {
                    bail!("{context}: duplicate variant '{}'", variant.name);
                }
                seen.push(variant.name.as_str());
                if variant.types.len() > MAX_TUPLE_ARITY {
                    bail!(
                        "{context}: variant '{}' carries {} payload types, exceeding the \
                         maximum of {MAX_TUPLE_ARITY}",
                        variant.name,
                        variant.types.len()
                    );
                }
                for type_ in &variant.types {
                    parse_type_str(type_)
                        .with_context(|| format!("{context}: variant '{}'", variant.name))?;
                }
            }
        }
    }

    Ok(())
}

/// The member table name a given kind is expected to use.
fn expected_member_table(kind: TypeKind) -> &'static str {
    match kind {
        TypeKind::Struct => "field",
        TypeKind::Enum => "case",
        TypeKind::Union => "variant",
    }
}

fn check_member_count(count: usize, context: &str) -> Result<()> {
    if count > MAX_MEMBERS_PER_TYPE {
        bail!("{context} declares {count} members, exceeding the maximum of {MAX_MEMBERS_PER_TYPE}");
    }
    Ok(())
}

fn check_case_name(name: &str, context: &str) -> Result<()> {
    if name.is_empty() {
        bail!("{context}: a case/variant has an empty name");
    }
    if name.len() > MAX_TYPE_NAME_LEN {
        bail!(
            "{context}: name '{name}' is {} characters, exceeding the \
             {MAX_TYPE_NAME_LEN}-character limit",
            name.len()
        );
    }
    Ok(())
}

/// Compare one declaration against the exported spec, if that name is exported.
fn reconcile_declared_type(
    declared: &DeclaredType,
    spec: &ContractSpec,
    build_label: &str,
) -> Result<()> {
    let name = declared.name.as_str();

    // A name exported under a different kind is always a contradiction: the
    // manifest and the contract cannot both be describing the same type.
    let exported_kind = exported_kind_of(name, spec);
    match (declared.kind, exported_kind) {
        // Not exported at all — exactly the internal-type case the manifest exists for.
        (_, None) => return Ok(()),
        (TypeKind::Struct, Some(ExportedKind::Struct)) => {
            let exported = &spec.structs[name];
            let exported_fields: &[stellar_xdr::curr::ScSpecUdtStructFieldV0] =
                exported.fields.as_ref();

            if exported_fields.len() != declared.fields.len() {
                bail!(
                    "struct '{name}' is declared with {} field(s) but the {build_label} build \
                     exports it with {}. Fix the declaration to match the contract.",
                    declared.fields.len(),
                    exported_fields.len()
                );
            }
            for (index, (declared_field, exported_field)) in
                declared.fields.iter().zip(exported_fields).enumerate()
            {
                let exported_name = exported_field.name.to_string();
                if declared_field.name != exported_name {
                    bail!(
                        "struct '{name}': field at position {index} is declared as '{}' but the \
                         {build_label} build exports '{exported_name}' there. Field order is \
                         layout, so this disagreement cannot be reconciled automatically.",
                        declared_field.name
                    );
                }
                let declared_type = parse_type_str(&declared_field.type_)?;
                if declared_type != exported_field.type_ {
                    bail!(
                        "struct '{name}': field '{}' is declared as `{}` but the {build_label} \
                         build exports it as `{}`.",
                        declared_field.name,
                        type_to_string(&declared_type),
                        type_to_string(&exported_field.type_)
                    );
                }
            }
        }
        (TypeKind::Enum, Some(ExportedKind::Enum)) => {
            let exported = &spec.enums[name];
            let exported_cases: &[stellar_xdr::curr::ScSpecUdtEnumCaseV0] = exported.cases.as_ref();
            reconcile_enum_cases(
                name,
                build_label,
                declared,
                exported_cases
                    .iter()
                    .map(|c| (c.name.to_string(), c.value))
                    .collect(),
            )?;
        }
        (TypeKind::Enum, Some(ExportedKind::ErrorEnum)) => {
            let exported = &spec.error_enums[name];
            let exported_cases: &[stellar_xdr::curr::ScSpecUdtErrorEnumCaseV0] =
                exported.cases.as_ref();
            reconcile_enum_cases(
                name,
                build_label,
                declared,
                exported_cases
                    .iter()
                    .map(|c| (c.name.to_string(), c.value))
                    .collect(),
            )?;
        }
        (TypeKind::Union, Some(ExportedKind::Union)) => {
            let exported = &spec.unions[name];
            let exported_cases: &[stellar_xdr::curr::ScSpecUdtUnionCaseV0] = exported.cases.as_ref();

            if exported_cases.len() != declared.variants.len() {
                bail!(
                    "union '{name}' is declared with {} variant(s) but the {build_label} build \
                     exports it with {}.",
                    declared.variants.len(),
                    exported_cases.len()
                );
            }
            for (index, (declared_variant, exported_case)) in
                declared.variants.iter().zip(exported_cases).enumerate()
            {
                let (exported_name, exported_types) = union_case_parts(exported_case);
                if declared_variant.name != exported_name {
                    bail!(
                        "union '{name}': variant at position {index} is declared as '{}' but the \
                         {build_label} build exports '{exported_name}' there. Variant order is \
                         the discriminant order.",
                        declared_variant.name
                    );
                }
                let declared_types = declared_variant
                    .types
                    .iter()
                    .map(|t| parse_type_str(t))
                    .collect::<Result<Vec<_>>>()?;
                if declared_types != exported_types {
                    bail!(
                        "union '{name}': variant '{}' is declared with payload ({}) but the \
                         {build_label} build exports payload ({}).",
                        declared_variant.name,
                        render_types(&declared_types),
                        render_types(&exported_types)
                    );
                }
            }
        }
        (declared_kind, Some(exported)) => {
            bail!(
                "'{name}' is declared as a {} but the {build_label} build exports it as a {}. \
                 An internal type must not shadow an exported type of a different shape — \
                 rename one of them.",
                declared_kind.label(),
                exported.label()
            );
        }
    }

    Ok(())
}

/// Compare declared enum cases against exported `(name, value)` pairs.
///
/// Unit enums are addressed by explicit discriminant rather than position, so
/// this compares the name→value mapping rather than declaration order.
fn reconcile_enum_cases(
    name: &str,
    build_label: &str,
    declared: &DeclaredType,
    exported: Vec<(String, u32)>,
) -> Result<()> {
    if exported.len() != declared.cases.len() {
        bail!(
            "enum '{name}' is declared with {} case(s) but the {build_label} build exports it \
             with {}.",
            declared.cases.len(),
            exported.len()
        );
    }
    for case in &declared.cases {
        match exported.iter().find(|(n, _)| n == &case.name) {
            None => bail!(
                "enum '{name}': case '{}' is declared but the {build_label} build does not \
                 export it.",
                case.name
            ),
            Some((_, exported_value)) if *exported_value != case.value => bail!(
                "enum '{name}': case '{}' is declared with discriminant {} but the \
                 {build_label} build exports {}.",
                case.name,
                case.value,
                exported_value
            ),
            Some(_) => {}
        }
    }
    Ok(())
}

/// The kinds a name can be exported under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportedKind {
    Struct,
    Enum,
    Union,
    ErrorEnum,
}

impl ExportedKind {
    fn label(&self) -> &'static str {
        match self {
            ExportedKind::Struct => "struct",
            ExportedKind::Enum => "enum",
            ExportedKind::Union => "union",
            ExportedKind::ErrorEnum => "error enum",
        }
    }
}

fn exported_kind_of(name: &str, spec: &ContractSpec) -> Option<ExportedKind> {
    if spec.structs.contains_key(name) {
        Some(ExportedKind::Struct)
    } else if spec.enums.contains_key(name) {
        Some(ExportedKind::Enum)
    } else if spec.unions.contains_key(name) {
        Some(ExportedKind::Union)
    } else if spec.error_enums.contains_key(name) {
        Some(ExportedKind::ErrorEnum)
    } else {
        None
    }
}

/// Split an exported union case into its name and payload types.
fn union_case_parts(case: &stellar_xdr::curr::ScSpecUdtUnionCaseV0) -> (String, Vec<ScSpecTypeDef>) {
    match case {
        stellar_xdr::curr::ScSpecUdtUnionCaseV0::VoidV0(v) => (v.name.to_string(), Vec::new()),
        stellar_xdr::curr::ScSpecUdtUnionCaseV0::TupleV0(t) => {
            let types: &[ScSpecTypeDef] = t.type_.as_ref();
            (t.name.to_string(), types.to_vec())
        }
    }
}

fn render_types(types: &[ScSpecTypeDef]) -> String {
    if types.is_empty() {
        "void".to_string()
    } else {
        types
            .iter()
            .map(type_to_string)
            .collect::<Vec<_>>()
            .join(", ")
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

    // -----------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------

    /// Parse without validating, so validation itself is what is under test.
    fn parse(toml_src: &str) -> StorageSchema {
        StorageSchema::from_toml_str(toml_src).expect("manifest should parse")
    }

    fn validation_error(toml_src: &str) -> String {
        parse(toml_src)
            .validate()
            .expect_err("manifest should have been rejected")
            .to_string()
    }

    #[test]
    fn a_type_cannot_be_declared_twice() {
        let error = validation_error(
            r#"
            [[storage_key]]
            name = "DataKey"
            kind = "enum"
              [[storage_key.case]]
              name = "Admin"
              value = 0

            [[value_type]]
            name = "DataKey"
            kind = "struct"
            "#,
        );
        assert!(error.contains("more than once"), "got: {error}");
    }

    #[test]
    fn member_table_must_match_the_declared_kind() {
        // A struct that supplies [[case]] entries would silently lose its
        // layout, so it is rejected rather than partly understood.
        let error = validation_error(
            r#"
            [[value_type]]
            name = "Thing"
            kind = "struct"
              [[value_type.case]]
              name = "Nope"
              value = 0
            "#,
        );
        assert!(error.contains("kind = \"struct\""), "got: {error}");
        assert!(error.contains("[[case]]"), "got: {error}");
    }

    #[test]
    fn duplicate_members_are_rejected() {
        let error = validation_error(
            r#"
            [[value_type]]
            name = "Position"
            kind = "struct"
              [[value_type.field]]
              name = "debt"
              type = "i128"
              [[value_type.field]]
              name = "debt"
              type = "u32"
            "#,
        );
        assert!(error.contains("duplicate field 'debt'"), "got: {error}");
    }

    #[test]
    fn two_enum_cases_cannot_share_a_discriminant() {
        let error = validation_error(
            r#"
            [[storage_key]]
            name = "Key"
            kind = "enum"
              [[storage_key.case]]
              name = "A"
              value = 0
              [[storage_key.case]]
              name = "B"
              value = 0
            "#,
        );
        assert!(error.contains("reuses discriminant 0"), "got: {error}");
    }

    #[test]
    fn an_enum_or_union_must_declare_members() {
        assert!(validation_error(
            r#"
            [[storage_key]]
            name = "Key"
            kind = "enum"
            "#,
        )
        .contains("at least one [[case]]"));

        assert!(validation_error(
            r#"
            [[storage_key]]
            name = "Key"
            kind = "union"
            "#,
        )
        .contains("at least one [[variant]]"));
    }

    #[test]
    fn unparseable_field_types_are_rejected_with_context() {
        let error = validation_error(
            r#"
            [[value_type]]
            name = "Position"
            kind = "struct"
              [[value_type.field]]
              name = "debt"
              type = "Vec<"
            "#,
        );
        assert!(error.contains("Position"), "error should name the type: {error}");
    }

    #[test]
    fn loading_from_disk_parses_and_validates() {
        let dir = std::env::temp_dir().join("sus-schema-load-test");
        std::fs::create_dir_all(&dir).unwrap();

        // A valid TOML manifest loads.
        let good = dir.join("good.storage-schema.toml");
        std::fs::write(
            &good,
            r#"
            [[value_type]]
            name = "PositionState"
            kind = "struct"
              [[value_type.field]]
              name = "collateral"
              type = "i128"
            "#,
        )
        .unwrap();
        let schema = StorageSchema::load_from_path(&good).expect("valid manifest should load");
        assert_eq!(schema.declared_count(), 1);

        // JSON is detected from the extension.
        let json = dir.join("good.json");
        std::fs::write(
            &json,
            r#"{ "value_type": [ { "name": "S", "kind": "struct", "field": [] } ] }"#,
        )
        .unwrap();
        assert_eq!(
            StorageSchema::load_from_path(&json).unwrap().declared_count(),
            1
        );

        // A manifest that parses but is invalid still fails at load time.
        let bad = dir.join("bad.storage-schema.toml");
        std::fs::write(
            &bad,
            r#"
            [[value_type]]
            name = "Broken"
            kind = "enum"
            "#,
        )
        .unwrap();
        assert!(StorageSchema::load_from_path(&bad).is_err());

        // An absent optional manifest is simply absent.
        assert!(StorageSchema::load_optional(&dir.join("missing.toml"))
            .unwrap()
            .is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // Reconciliation against the exported spec
    // -----------------------------------------------------------------

    use stellar_xdr::curr::{
        ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0, ScSpecUdtStructFieldV0, ScSpecUdtStructV0, StringM,
        VecM as XdrVecM,
    };

    fn spec_with_struct(name: &str, fields: &[(&str, ScSpecTypeDef)]) -> ContractSpec {
        let mut spec = ContractSpec::default();
        let xdr_fields: Vec<ScSpecUdtStructFieldV0> = fields
            .iter()
            .map(|(fname, ftype)| ScSpecUdtStructFieldV0 {
                doc: StringM::default(),
                name: (*fname).try_into().unwrap(),
                type_: ftype.clone(),
            })
            .collect();
        spec.structs.insert(
            name.to_string(),
            ScSpecUdtStructV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: name.try_into().unwrap(),
                fields: XdrVecM::try_from(xdr_fields).unwrap(),
            },
        );
        spec
    }

    fn spec_with_enum(name: &str, cases: &[(&str, u32)]) -> ContractSpec {
        let mut spec = ContractSpec::default();
        let xdr_cases: Vec<ScSpecUdtEnumCaseV0> = cases
            .iter()
            .map(|(cname, value)| ScSpecUdtEnumCaseV0 {
                doc: StringM::default(),
                name: (*cname).try_into().unwrap(),
                value: *value,
            })
            .collect();
        spec.enums.insert(
            name.to_string(),
            ScSpecUdtEnumV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: name.try_into().unwrap(),
                cases: XdrVecM::try_from(xdr_cases).unwrap(),
            },
        );
        spec
    }

    const POSITION_SCHEMA: &str = r#"
        [[value_type]]
        name = "PositionState"
        kind = "struct"
          [[value_type.field]]
          name = "collateral"
          type = "i128"
          [[value_type.field]]
          name = "debt"
          type = "i128"
    "#;

    /// The central case the manifest exists for: a purely internal type that
    /// the exported spec has never heard of reconciles cleanly.
    #[test]
    fn a_non_exported_type_reconciles_trivially() {
        let schema = parse(POSITION_SCHEMA);
        schema
            .reconcile_with_spec(&ContractSpec::default(), "old")
            .expect("an internal type need not be exported");
    }

    #[test]
    fn a_declaration_matching_the_exported_spec_reconciles() {
        let schema = parse(POSITION_SCHEMA);
        let spec = spec_with_struct(
            "PositionState",
            &[
                ("collateral", ScSpecTypeDef::I128),
                ("debt", ScSpecTypeDef::I128),
            ],
        );
        schema.reconcile_with_spec(&spec, "new").expect("layouts agree");
    }

    #[test]
    fn a_manifest_that_contradicts_field_order_fails_loudly() {
        let schema = parse(POSITION_SCHEMA);
        // Exported spec has the fields the other way round.
        let spec = spec_with_struct(
            "PositionState",
            &[
                ("debt", ScSpecTypeDef::I128),
                ("collateral", ScSpecTypeDef::I128),
            ],
        );
        let error = schema
            .reconcile_with_spec(&spec, "old")
            .expect_err("contradiction must be rejected")
            .to_string();
        assert!(error.contains("disagrees"), "got: {error}");
    }

    #[test]
    fn a_manifest_that_contradicts_a_field_type_fails_loudly() {
        let schema = parse(POSITION_SCHEMA);
        let spec = spec_with_struct(
            "PositionState",
            &[
                ("collateral", ScSpecTypeDef::I128),
                ("debt", ScSpecTypeDef::U32), // declared as i128
            ],
        );
        assert!(schema.reconcile_with_spec(&spec, "old").is_err());
    }

    /// An internal type must not shadow an exported name of a different shape,
    /// because then it is ambiguous which layout governs storage.
    #[test]
    fn an_internal_type_shadowing_an_exported_type_of_another_kind_fails() {
        let schema = parse(POSITION_SCHEMA);
        let spec = spec_with_enum("PositionState", &[("Active", 0)]);
        let error = schema
            .reconcile_with_spec(&spec, "new")
            .expect_err("shadowing a different kind must be rejected")
            .to_string();
        assert!(error.contains("disagrees"), "got: {error}");
    }

    #[test]
    fn enum_discriminants_are_reconciled_by_name_not_position() {
        let schema = parse(
            r#"
            [[storage_key]]
            name = "Status"
            kind = "enum"
              [[storage_key.case]]
              name = "Paused"
              value = 1
              [[storage_key.case]]
              name = "Active"
              value = 0
            "#,
        );

        // Same name->value mapping, listed in a different order: unit enums are
        // addressed by discriminant, so this agrees.
        let spec = spec_with_enum("Status", &[("Active", 0), ("Paused", 1)]);
        schema
            .reconcile_with_spec(&spec, "old")
            .expect("discriminant mapping matches");

        // A shifted discriminant is a genuine contradiction.
        let shifted = spec_with_enum("Status", &[("Active", 0), ("Paused", 2)]);
        assert!(schema.reconcile_with_spec(&shifted, "old").is_err());
    }

    // -----------------------------------------------------------------
    // Resolution into the diff engine's model
    // -----------------------------------------------------------------

    /// The whole point of the manifest: a type the exported spec never mentions
    /// still becomes a first-class, diff-ready `ScSpecUdt`.
    #[test]
    fn a_non_exported_struct_resolves_to_a_diffable_udt() {
        let resolved = parse(POSITION_SCHEMA).resolve().expect("should resolve");

        let position = resolved
            .spec
            .structs
            .get("PositionState")
            .expect("declared struct should resolve into the spec");

        assert_eq!(position.name.to_string(), "PositionState");
        let fields: &[ScSpecUdtStructFieldV0] = position.fields.as_ref();
        // Declaration order is preserved, because that order *is* the layout.
        assert_eq!(fields[0].name.to_string(), "collateral");
        assert_eq!(fields[0].type_, ScSpecTypeDef::I128);
        assert_eq!(fields[1].name.to_string(), "debt");

        assert_eq!(resolved.value_type_count(), 1);
        assert_eq!(resolved.key_type_count(), 0);
    }

    #[test]
    fn a_storage_key_union_resolves_with_void_and_tuple_variants() {
        let resolved = parse(
            r#"
            [[storage_key]]
            name = "DataKey"
            kind = "union"
              [[storage_key.variant]]
              name = "Admin"
              [[storage_key.variant]]
              name = "Position"
              type = ["Address"]
            "#,
        )
        .resolve()
        .expect("should resolve");

        let key = resolved.spec.unions.get("DataKey").expect("union resolved");
        let cases: &[ScSpecUdtUnionCaseV0] = key.cases.as_ref();
        assert_eq!(cases.len(), 2);

        // Variant order is discriminant order, so it must survive resolution.
        match &cases[0] {
            ScSpecUdtUnionCaseV0::VoidV0(v) => assert_eq!(v.name.to_string(), "Admin"),
            other => panic!("expected a void variant first, got {other:?}"),
        }
        match &cases[1] {
            ScSpecUdtUnionCaseV0::TupleV0(t) => {
                assert_eq!(t.name.to_string(), "Position");
                let types: &[ScSpecTypeDef] = t.type_.as_ref();
                assert_eq!(types, &[ScSpecTypeDef::Address]);
            }
            other => panic!("expected a tuple variant second, got {other:?}"),
        }

        assert_eq!(resolved.key_type_count(), 1);
        assert_eq!(
            resolved.meta["DataKey"].role,
            DeclarationRole::StorageKey
        );
        assert_eq!(resolved.meta["DataKey"].durability, Durability::Persistent);
    }

    #[test]
    fn an_enum_resolves_with_its_declared_discriminants() {
        let resolved = parse(
            r#"
            [[value_type]]
            name = "Status"
            kind = "enum"
            durability = "instance"
              [[value_type.case]]
              name = "Active"
              value = 0
              [[value_type.case]]
              name = "Closed"
              value = 7
            "#,
        )
        .resolve()
        .expect("should resolve");

        let status = resolved.spec.enums.get("Status").expect("enum resolved");
        let cases: &[ScSpecUdtEnumCaseV0] = status.cases.as_ref();
        assert_eq!(cases[1].name.to_string(), "Closed");
        assert_eq!(cases[1].value, 7);
        assert_eq!(resolved.meta["Status"].durability, Durability::Instance);
    }

    /// A type declared only in the manifest and referenced only by another
    /// declared type still resolves — this is the "non-exported type referenced
    /// only by the storage schema" case.
    #[test]
    fn references_between_declared_types_resolve() {
        let schema = parse(
            r#"
            [[value_type]]
            name = "Account"
            kind = "struct"
              [[value_type.field]]
              name = "position"
              type = "PositionState"

            [[value_type]]
            name = "PositionState"
            kind = "struct"
              [[value_type.field]]
              name = "debt"
              type = "i128"
            "#,
        );

        assert!(
            schema.unresolved_references(None).is_empty(),
            "PositionState is declared, so the reference resolves"
        );

        let resolved = schema.resolve().expect("should resolve");
        assert!(resolved.spec.structs.contains_key("Account"));
        assert!(resolved.spec.structs.contains_key("PositionState"));
    }

    #[test]
    fn dangling_references_are_reported_rather_than_hidden() {
        let schema = parse(
            r#"
            [[value_type]]
            name = "Account"
            kind = "struct"
              [[value_type.field]]
              name = "balances"
              type = "Map<Address, Vec<Mystery>>"
            "#,
        );

        // Nothing declares or exports `Mystery`, so its layout is unknown.
        assert_eq!(schema.unresolved_references(None), vec!["Mystery".to_string()]);

        // Once the build exports it, the reference resolves.
        let exported = spec_with_struct("Mystery", &[("x", ScSpecTypeDef::U32)]);
        assert!(schema.unresolved_references(Some(&exported)).is_empty());
    }

    #[test]
    fn oversized_schemas_are_refused() {
        let mut schema = StorageSchema::default();
        for index in 0..(MAX_DECLARED_TYPES + 1) {
            schema.value_types.push(DeclaredType {
                name: format!("T{index}"),
                kind: TypeKind::Struct,
                doc: None,
                durability: None,
                fields: Vec::new(),
                cases: Vec::new(),
                variants: Vec::new(),
            });
        }
        let error = schema.validate().expect_err("oversized schema").to_string();
        assert!(error.contains("exceeding the supported maximum"), "got: {error}");
    }
}
